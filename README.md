#### Wrapper for libwireshark

As libwireshark is not public API, it is prone to change and break non-official tools depending on it.
This project aims to provide a thin frequently-updated wrapper around the core capture/dissect functionality that other applications can then link against.


Tested working with Wireshark `v2.2.4` on macOS Sierra.

#### Usage

    mkdir build && cd build
    cmake ..
    make
    ./simple_print -f ../test/1.pcap

#### License

Code is released under same terms as [tshark](https://github.com/boundary/wireshark/blob/master/tshark.c), which it's based on (GNU GPL2.0+). It contains [code by Sun Wang](https://github.com/sunwxg/decode_by_libwireshark), originally under the MIT license.
