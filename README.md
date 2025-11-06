# Azul Plugin Maco

An Azul Python plugin that maps config extractors written using the Maco format to Azul.

The intent of this plugin is to evolve with the config decoders. At the moment it is quite bare-bones
and feedback will determine how data is mapped in the future.

## Development Installation

For Python3.10 specific dev version is required `sudo apt install python3.10-dev`

To install azul-plugin-maco for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-extractors

Usage on local files:

```bash
azul-plugin-maco -c scripts path/to/maco/extractors malware.file
```

To specify custom features, specify this as an environmental variable:

```bash
PLUGIN_CUSTOM_FEATURES='{"cool_cats": "meow|string"}' azul-plugin-maco \
  -c scripts path/to/maco/extractors malware.file
```

Example Output:

Obtained from executing the CobaltStrike extractor against a single CobaltStrike sample.

```
----- AzulPluginMaco-CobaltStrike results -----
COMPLETED

events (1)

event for f9f8b98ab1dc1db7cb708b62e31652038a520b2e5b9d887fa42cb193cdd24007:None
  {}
  output data streams (1):
    2017 bytes - EventData(hash='8bbeb771b54c904366adefb47754dc8a6a31d7df8b4c32730377356f82069a7f', label='text')
  output features:
                   algorithm: communication - RSA
                              config - XOR
     algorithm_communication: RSA
            algorithm_config: XOR
                      attack: T1001.003
                              T1003.001
                              T1003.002
                              T1005
                              T1007
                              T1012
                              T1016
                              T1018
                              T1021.001
                              T1021.002
                              T1021.003
                              T1021.004
                              T1021.006
                              T1027
                              T1027.005
                              T1029
                              T1030
                              T1046
                              T1047
                              T1049
                              T1055
                              T1055.001
                              T1055.012
                              T1056.001
                              T1057
                              T1059.001
                              T1059.003
                              T1059.005
                              T1059.006
                              T1059.007
                              T1068
                              T1069.001
                              T1069.002
                              T1070.006
                              T1071
                              T1071.001
                              T1071.004
                              T1078.002
                              T1078.003
                              T1083
                              T1087.002
                              T1090.001
                              T1090.004
                              T1095
                              T1105
                              T1106
                              T1112
                              T1113
                              T1132.001
                              T1134.001
                              T1134.003
                              T1134.004
                              T1135
                              T1137.001
                              T1140
                              T1185
                              T1197
                              T1203
                              T1218.011
                              T1518
                              T1543.003
                              T1548.002
                              T1548.003
                              T1550.002
                              T1553.002
                              T1562.001
                              T1564.010
                              T1569.002
                              T1572
                              T1573.001
                              T1573.002
                              T1620
                builder_hash: 3f4303623091e876166764e8d5ba2c95
             c2_instructions: Print
         capability_disabled: cobaltstrike_bcfg_caution
                              cobaltstrike_bstage_cleanup
                              cobaltstrike_http_post_chunk
          capability_enabled: cobaltstrike_bproc_inject_start_rwx
                              cobaltstrike_bproc_inject_use_rwx
                              cobaltstrike_buses_cookies
                              cobaltstrike_crypto_scheme
                              cobaltstrike_sleep_mask
                    category: apt
                              backdoor
                              downloader
                              rat
                              trojan
                  connection: c2 - 119.3.152.152/g.pixel
                              c2 - 119.3.152.152/submit.php
                              c2 - http://119.3.152.152:80/g.pixel
                              c2 - http://119.3.152.152:80/submit.php
               connection_c2: 119.3.152.152/g.pixel
                              119.3.152.152/submit.php
                              http://119.3.152.152:80/g.pixel
                              http://119.3.152.152:80/submit.php
                      family: CobaltStrike
               header_fields: application/octet-stream - 119.3.152.152/submit.php - Content-Type
                              application/octet-stream - http://119.3.152.152:80/submit.php - Content-Type
               header_values: Content-Type - 119.3.152.152/submit.php - application/octet-stream
                              Content-Type - http://119.3.152.152:80/submit.php - application/octet-stream
                     headers: 119.3.152.152/submit.php - Content-Type: application/octet-stream
                              http://119.3.152.152:80/submit.php - Content-Type: application/octet-stream
           http_get_metadata: ConstHeaders: [], ConstParams: [], Metadata: [base64, header "Cookie"], SessionId: [], Output: []
          http_post_metadata: ConstHeaders: [Content-Type: application/octet-stream], ConstParams: [], Metadata: [], SessionId: [parameter "id"], Output: [print]
                  inject_exe: %windir%\sysnative\rundll32.exe
                              %windir%\syswow64\rundll32.exe
                         key: config_XOR - 0xa9
    malleable_pe_entry_point: 113972
    malleable_pe_export_name: beacon.dll
     malleable_pe_image_size: 315392
    malleable_pe_rich_header: 2686017462e76f2762e76f2762e76f270409bd27fae76f27fc47a82763e76f279321a0274be76f279321a127eae76f279321a22768e76f276b9ffc2769e76f2762e76e27ade76f270409a12751e76f270409a52763e76f270409a32763e76f275269636862e76f27
          malleable_pe_times: 2020-11-03T01:31:34
                              2020-11-03T01:31:35
                    max_size: 119.3.152.152/g.pixel - 1048576
                              http://119.3.152.152:80/g.pixel - 1048576
                      method: 119.3.152.152/g.pixel - GET
                              http://119.3.152.152:80/g.pixel - GET
                              119.3.152.152/submit.php - POST
                              http://119.3.152.152:80/submit.php - POST
                  public_key: communication_RSA - 30819f300d06092a864886f70d010101050003818d0030818902818100e7736de30be2b00730a980b9bf6621b5fc750d1038608c89d664c1a3c30e35185577cdf357e8ad78c0c7c40ff52b9460f1c8a206a9bb0c6279fb6bb3a0f0056dec54247a290a3c626e29721b637d7109ea2c5fd705d04663bc99d9b5f39a930314dcd9a4eaa789166b2e4658b2ad75f91b5efbbaccd43fa4ef64a8d6d31827830203010001
                 sleep_delay: 60000
              smb_frame_data: 0004
              tcp_frame_data: 0004
                  user_agent: 119.3.152.152/g.pixel - Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)
                              119.3.152.152/submit.php - Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)
                              http://119.3.152.152:80/g.pixel - Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)
                              http://119.3.152.152:80/submit.php - Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)
                     version: 4.2
                   watermark: 99032177 (0x5e71c71)

Feature key:
  algorithm:  all encryption algorithms
  algorithm_communication:  algorithm of encrypted communications
  algorithm_config:  algorithm of encrypted config
  attack:  mitre att&ck reference ids, e.g. 'T1129'
  builder_hash:  hash of the implant builder
  c2_instructions:  modifications applied to comms structure
  capability_disabled:  capabilities of the malware disabled in config
  capability_enabled:  capabilities of the malware enabled in config
  category:  capability/purpose of the malware
  connection:  all connections
  connection_c2:  a connection for c2
  family:  family of malware that was detected
  header_fields:  http header fields
  header_values:  http header values
  headers:  http headers
  http_get_metadata:  modifications applied to http get requests
  http_post_metadata:  modifications applied to http post requests
  inject_exe:  name of executable to inject into
  key:  private/symmetric key
  malleable_pe_entry_point:  fake pe entrypoint set by the builder
  malleable_pe_export_name:  fake pe export name set by the builder
  malleable_pe_image_size:  fake pe image size set by the builder
  malleable_pe_rich_header:  fake pe rich header set by the builder
  malleable_pe_times:  fake pe timestamps set by the builder
  max_size:  max size of http body
  method:  http method of request
  public_key:  public key
  sleep_delay:  time to sleep/delay execution (milliseconds)
  smb_frame_data:  data to append to smb packets
  tcp_frame_data:  date to append to tcp packets
  user_agent:  user agent of http request/response
  version:  version/variant of malware
  watermark:  licensing watermark
```

Automated usage in system:

```
azul-plugin-maco --server http://azul-dispatcher.localnet/
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
