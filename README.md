#### Wrapper for libwireshark

[![Build Status](https://travis-ci.org/epl-viz/liblibwireshark.svg?branch=master)](https://travis-ci.org/epl-viz/liblibwireshark)

As libwireshark is not public API, it is prone to change and break non-official tools depending on it.
This project aims to provide a thin frequently-updated wrapper around the core capture/dissect functionality that other applications can then link against.


(Last) tested working with Wireshark `v2.4.5`.

#### Usage

    mkdir build && cd build
    cmake ..
    make
    ./simple_print -t text ../samples/1-EPL-Frame.pcapng

#### License

Code is released under same terms as [tshark](https://github.com/boundary/wireshark/blob/master/tshark.c), which it's based on (GNU GPL2.0+). It contains [code by Sun Wang](https://github.com/sunwxg/decode_by_libwireshark), originally under the MIT license.
