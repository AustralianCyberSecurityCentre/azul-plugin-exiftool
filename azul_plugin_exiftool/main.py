"""Extract metadata from many filetypes using opensource ExifTool."""

import contextlib
import datetime
import json
import os
import re
import subprocess  # nosec B404

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)


def strlist(s):
    """Given a str with a comma-separated list of values, return as list."""
    return [x.strip() for x in s.split(",") if x.strip()]


# redundant fields and those derived from filesystem not content
IGNORED_FIELDS = [
    "SourceFile",
    "ExifToolVersion",
    "FileName",
    "Directory",
    "FileSize",
    "FileModifyDate",
    "FileAccessDate",
    "FileInodeChangeDate",
    "FilePermissions",
]

# Fields to ignore when they are very long.
IGNORED_FIELDS_WHEN_TOO_LONG = ["Mappings", "Comment"]

# dict of exiftool field name to feature field, val_func tuple
# Can field names collide between diff file types? eg. 'Comments'
MAPPED_FIELDS = {
    "MIMEType": ("mime", str),
    # 'FileType': ('fileformat', str),
    "MachineType": ("pe_machine", str),
    "Subsystem": ("pe_subsystem", str),
    "SubsystemVersion": ("pe_subsystem_version", str),
    "CodeSize": ("pe_code_size", int),
    "LinkerVersion": ("pe_linker_version", str),
    "InitializedDataSize": ("pe_init_data_size", int),
    "UninitializedDataSize": ("pe_uninit_data_size", int),
    "OSVersion": ("pe_os_version", str),
    "ImageVersion": ("pe_image_version", str),
    "ImageFileCharacteristics": ("pe_characteristics", strlist),
    "CompanyName": ("pe_publisher", str),
    "Comments": ("pe_comments", str),
    "LegalCopyright": ("pe_copyright", str),
    "FileDescription": ("pe_description", str),
    "FileVersionNumber": ("pe_file_version", str),  # from fixed not strings block
    "InternalName": ("pe_internal_name", str),
    "OriginalFileName": ("pe_original_name", str),
    "ProductName": ("pe_product_name", str),
    "ProductVersionNumber": ("pe_product_version", str),  # from fixed not strings block
}


class AzulPluginExifTool(BinaryPlugin):
    """Extract metadata from many filetypes using opensource ExifTool."""

    SETTINGS = add_settings(
        # No input feature or content filters - scan everything
        filter_data_types={"content": []},
        filter_max_content_size=(int, 200 * 1024 * 1024),
        timeout=(int, 90),
    )
    CONTACT = "ASD's ACSC"
    VERSION = "2025.09.30"
    FEATURES = [
        # generic catch all feature
        Feature(
            "exif_metadata", "Metadata field extracted by exiftool, label is the field name", type=FeatureType.String
        ),
        # specifically mapped features for correlation between plugins
        Feature("mime", "Magic mime type", type=FeatureType.String),
        Feature("pe_characteristics", "Characteristics as defined in the PE file header", type=FeatureType.String),
        Feature("pe_code_size", "Code size as defined in PE optional header", type=FeatureType.Integer),
        Feature("pe_comments", "Comments section from VERSIONINFO", type=FeatureType.String),
        Feature("pe_copyright", "Copyright notice from VERSIONINFO", type=FeatureType.String),
        Feature("pe_description", "Description of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_file_version", "Version of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_image_version", "Image version as defined in PE optional header", type=FeatureType.String),
        Feature(
            "pe_init_data_size", "Initialised data size as defined in PE optional header", type=FeatureType.Integer
        ),
        Feature("pe_internal_name", "Internal name of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_linker_version", "Linker version as defined in PE optional header", type=FeatureType.String),
        Feature("pe_machine", "Machine as defined in PE file header", type=FeatureType.String),
        Feature("pe_original_name", "Original name of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_os_version", "Operating system version as defined in PE optional header", type=FeatureType.String),
        Feature("pe_product_name", "Product name of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_product_version", "Product version of the file from VERSIONINFO", type=FeatureType.String),
        Feature("pe_publisher", "Company name of the file publisher from VERSIONINFO", type=FeatureType.String),
        Feature("pe_subsystem", "Target subsystem as defined in PE optional header", type=FeatureType.String),
        Feature("pe_subsystem_version", "Subsystem version as defined in PE optional header", type=FeatureType.String),
        Feature(
            "pe_uninit_data_size", "Uninitialised data size as defined in PE optional header", type=FeatureType.Integer
        ),
    ]

    def execute(self, job: Job):
        """Run exiftool on cmdline, parsing json response content into features."""
        path = job.get_data().get_filepath()
        # Check if binary is full of zeros and return malformed if so.
        if AzulPluginExifTool.is_binary_file_full_of_zeros(path):
            return self.is_malformed("Binary is full of zeros.")

        # I believe we want to force UTC as some date times are reported in local tz
        # however, we want to ensure this doesn't override tz in fields that store their
        # own tz info, so not sure if there's a way to force preserve that.
        env = dict(os.environ)
        env["TZ"] = "UTC"
        p = subprocess.run(  # noqa: S603, S607 # nosec B603 B607
            ["exiftool", "-json", path],
            env=env,
            capture_output=True,
            timeout=self.cfg.timeout,
        )
        if p.returncode and b"Unknown file type" in p.stdout:
            # exiftool treats unknown types as error
            return State(State.Label.OPT_OUT, "Unknown file type")
        elif p.returncode:
            # raise anything else as processing error
            err_msg = p.stderr.decode("utf-8")
            with contextlib.suppress(Exception):
                # Attempt to load the output as json and format the error message nicely.
                if len(err_msg) == 0:
                    err_msg = p.stdout.decode("utf-8")
                    final_message = []
                    for val in json.loads(err_msg.strip()):
                        if len(val) == 0:
                            continue
                        final_message.append(val["Error"])
                    if len(final_message) > 0:
                        err_msg = "\n".join(final_message)
            # Entire file is a single binary character and is therefore malformed.
            if err_msg.startswith("Entire file is binary"):
                return self.is_malformed(err_msg)

            if re.match("First [0-9].* of file is binary (zeros|0x..'s)", err_msg):
                return State(State.Label.OPT_OUT, message=err_msg)
            return State(
                State.Label.ERROR_EXCEPTION,
                message=err_msg,
            )

        features, truncated_field_names = self.features(p.stdout.decode("utf-8"))
        self.add_many_feature_values(features)
        if len(truncated_field_names) > 0:
            return State(
                State.Label.COMPLETED_WITH_ERRORS,
                message=f"Completed but the following fields were truncated {','.join(truncated_field_names)}",
            )

    def features(self, jsonstring) -> tuple[dict[str, list[FeatureValue]], list[str]]:
        """Given exiftool output in json format, transform into a features dict.

        returns: a dictionary of features to add and a boolean indicating if any values were truncated.
        """
        features = {}
        truncated_field_names = []
        # returns a list of dicts containing key:value metadata attributes
        # May be future issues with field name collisions.
        for j in json.loads(jsonstring):
            for field, val in j.items():
                if val in ("(none)", ""):  # allow 0 as valid int
                    continue
                if field in IGNORED_FIELDS:
                    continue
                if field in MAPPED_FIELDS:
                    name, f = MAPPED_FIELDS[field]
                    features[name] = f(val)
                if not isinstance(val, (int, float, str, datetime.datetime, bytes)):
                    # skip bad output
                    continue
                if isinstance(val, (str, bytes)) and len(val) > self.cfg.max_value_length:
                    if field in IGNORED_FIELDS_WHEN_TOO_LONG:
                        continue
                    else:
                        truncated_field_names.append(field)
                        val = val[: self.cfg.max_value_length]
                # regardless, always set the generic feature
                features.setdefault("exif_metadata", []).append(FV(str(val), label=field))
        return features, truncated_field_names

    def is_binary_file_full_of_zeros(file_path):
        """Scan file for zeros."""
        with open(file_path, "rb") as file:
            byte = file.read(1)
            while byte:
                if byte != b"\x00":
                    return False
                byte = file.read(1)
        return True


def main():
    """Run via command-line."""
    cmdline_run(plugin=AzulPluginExifTool)


if __name__ == "__main__":
    main()
