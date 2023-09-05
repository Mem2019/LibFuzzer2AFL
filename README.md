# LibFuzzer2AFL

LibFuzzer2AFL converts libFuzzer executable with custom mutator to AFL++ custom mutator shared library. To use it, simply compile the target program with `compiler` and `compiler++`.

As an example:

```bash
# Fetch and compile LibFuzzer2AFL.
git clone https://github.com/Mem2019/LibFuzzer2AFL.git && cd LibFuzzer2AFL
git submodule update --init
make clean all

# Use LibFuzzer2AFL to compile a libFuzzer executable, which generates a AFL++ custom mutator library.
git clone https://github.com/Mem2019/libprotobuf-mutator.git
cd libprotobuf-mutator && mkdir build && cd build
cmake .. -DCMAKE_C_COMPILER=$PWD/../../compiler -DCMAKE_CXX_COMPILER=$PWD/../../compiler++ -DCMAKE_BUILD_TYPE=Release -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON
cd examples/learning/3_libprotobuf_libfuzzer_custom_mutator/ && make
ls -l libprotobuf_libfuzzer_custom_mutator # AFL++ custom mutator
```
