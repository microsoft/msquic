# Fuzzing

This directory is used for fuzzing.  
[OSS-Fuzz] automatically builds, runs and reports issue if there is any problem.


## Write fuzzing
[OSS-Fuzz] uses [LibFuzzer] by default which is included in clang.  
Refer [Libfuzzer] official document if you want more detail.

## Run locally
You can build and run code by yourself. [OSS-Fuzz] offers convenient scripts

```sh
$ cd $PATH_TO_OSS_FUZZ
# build Docker image
$ python infra/helper.py build_image msquic
# build fuzzing code, memory sanitizer is not supported yet
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> msquic
# run fuzzing
$ python infra/helper.py run_fuzzer msquic $YOUR_COOL_FUZZING
```
Refer [OSS-Fuzz official document] for more detail

## Reproduce and debug issue
[Reproduce]  
[Debug]

## Monitor your fuzzing
Once fuzzing is deployed on OSS-Fuzz infra, it continuously run and report issue if it detects  
### Receive notification
List your email under [auto_ccs] or [vendor_ccs] section in [project.yaml]  
Most of developer should be under [vendor_ccs]. Please follow instruction in [vendor_ccs] and feel free to create PR and let us know on issue or discussion.

### Login OSS-Fuzz dashabord
Your email need to be associated with google account

## Before adding change....
Please go to [msquic project directory] in [OSS-Fuzz] whether your change can be run without issue.  
You might need to change `Dockerfile` and/or `build.sh` for installing libraries, COPYing fuzzing source, configuration files and build options.



[OSS-Fuzz]: https://github.com/google/oss-fuzz
[OSS-Fuzz official document]: https://google.github.io/oss-fuzz
[msquic project directory]: https://github.com/google/oss-fuzz/tree/master/projects/msquic
[LibFuzzer]: https://llvm.org/LibFuzzer
[Reproduce]: https://google.github.io/oss-fuzz/advanced-topics/reproducing/
[Debug]: https://google.github.io/oss-fuzz/advanced-topics/debugging/
[project.yaml]: https://github.com/google/oss-fuzz/blob/master/projects/msquic/project.yaml
[auto_ccs]: https://google.github.io/oss-fuzz/getting-started/new-project-guide/#primary
[vendor_ccs]: https://google.github.io/oss-fuzz/getting-started/new-project-guide/#vendor
