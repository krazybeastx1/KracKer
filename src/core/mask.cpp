#include "KracKer/mask.hpp"

// MaskProcessor and MaskIterator are header-only so that both the cracker and
// the unit tests can use them; this translation unit keeps them in the build.
namespace KracKer {
namespace {
[[maybe_unused]] const void* mask_tu_anchor = nullptr;
}
} // namespace KracKer
