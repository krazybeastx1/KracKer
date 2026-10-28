#include "KracKer/hash_argon2.hpp"
#include <memory>
#include <sstream>

namespace KracKer {

std::unique_ptr<Argon2Hash> Argon2Hash::create_argon2i() {
    return std::make_unique<Argon2Hash>(Variant::Argon2i);
}

std::unique_ptr<Argon2Hash> Argon2Hash::create_argon2d() {
    return std::make_unique<Argon2Hash>(Variant::Argon2d);
}

std::unique_ptr<Argon2Hash> Argon2Hash::create_argon2id() {
    return std::make_unique<Argon2Hash>(Variant::Argon2id);
}

Argon2Hash::~Argon2Hash() {
    // Explicit destructor definition for vtable emission
}

} // namespace KracKer