#include "../tests/support/qualification_pipeline.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    qualification::check_pipeline(data, size);
    return 0;
}
