# Azul Plugin Exiftool

Uses https://exiftool.org/ utility to extract metadata from files
and publishes as AZUL features.

## Development Installation

To install azul-plugin-exiftool for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-exiftool

Supports any file type and uses `exiftool` to extract metadata.

Usage on local files:

```
azul-plugin-exiftool DX8VB.DLL
```

Example Output:

```
----- ExifTool results -----
OK

Output features:
     pe_init_data_size: 475136
  pe_subsystem_version: 4.0
      pe_image_version: 5.1
         pe_os_version: 5.1
            pe_machine: Intel 386 or later, and compatibles
          pe_code_size: 294912
              mimetype: application/octet-stream
   pe_uninit_data_size: 798720
          pe_publisher: Microsoft Corporation
     pe_linker_version: 6.2
         exif_metadata: FileSubtype - 0
                        EntryPoint - 0x10b7f0
                        FileFlagsMask - 0x30003f
                        TimeStamp - 2000:10:21 09:22:24+00:00
                        CodeSize - 294912
                        SubsystemVersion - 4.0
                        FileVersion - 4.08.00.0400
                        ProductVersion - 4.08.00.0400
                        FileVersionNumber - 4.8.0.400
                        ProductVersionNumber - 4.8.0.400
                        InitializedDataSize - 475136
                        ImageVersion - 5.1
                        OSVersion - 5.1
                        LinkerVersion - 6.2
                        UninitializedDataSize - 798720
                        LegalCopyright - Copyright © Microsoft Corp. 1994-2000
                        ObjectFileType - Dynamic link library
                        LanguageCode - English (U.S.)
                        MachineType - Intel 386 or later, and compatibles
                        CompanyName - Microsoft Corporation
                        FileDescription - Microsoft DirectX for Visual Basic
                        ProductName - Microsoft® DirectX for Windows®  95 and 98
                        PEType - PE32
                        FileType - Win32 DLL
                        FileOS - Windows 16-bit
                        Subsystem - Windows GUI
                        CharacterSet - Windows, Latin1
                        MIMEType - application/octet-stream
                        FileTypeExtension - dll
                        InternalName - dx8vb.dll
                        OriginalFileName - dx8vb.dll
    pe_product_version: 4.8.0.400
          pe_subsystem: Windows GUI


Feature key:
  pe_init_data_size:  Initialised data size as defined in PE optional header
  pe_subsystem:  Target subsystem as defined in PE optional header
  pe_subsystem_version:  Subsystem version as defined in PE optional header
  pe_os_version:  Operating system version as defined in PE optional header
  pe_machine:  Machine as defined in PE file header
  pe_code_size:  Code size as defined in PE optional header
  mimetype:  Magic mime type
  pe_uninit_data_size:  Uninitialised data size as defined in PE optional header
  pe_publisher:  Recorded publisher of the PE file
  pe_linker_version:  Linker version as defined in PE optional header
  exif_metadata:  Metadata field extracted by exiftool, label is the field name
  pe_product_version:  Recorded product version of the PE file
  pe_image_version:  Image version as defined in PE optional header

```

Automated usage in system:

```
azul-plugin-exiftool --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.

## Upgrading exiftool for local dev

If test cases for this repo are failing it's likely due to the version of exiftool you are running.
For example Ubuntu 24.04 runs an older version of exiftool compared to debian 13.

To rectify this issue you can build exiftool from source, to do that.

clone the exif tool repo:
`git clone https://github.com/exiftool/exiftool.git`

You can then manually build and install exiftool with the commands listed in the exiftool git repo:

```bash
# enter the git repo
cd exiftool

perl Makefile.PL
make
make test
sudo make install

# Recommended to delete the git repo after installing.
#rm -rf exiftool
```
