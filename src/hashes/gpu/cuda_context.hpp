#pragma once

#include "KracKer/hash_interface.hpp"
#include <cuda_runtime.h>
#include <string>
#include <vector>

namespace KracKer {

class CUDAContext : public IGPUContext {
public:
    CUDAContext() = default;
    ~CUDAContext() override { shutdown(); }

    bool initialize(uint32_t device_id) override;
    void shutdown() override;

    bool compile_kernel(const std::string& source, const std::string& kernel_name) override;
    bool set_kernel_arg(uint32_t index, const void* data, size_t size) override;
    bool set_buffer_arg(uint32_t index, void* buffer, size_t size) override;

    bool execute_kernel(uint64_t global_size, uint64_t local_size) override;
    bool read_buffer(void* host_ptr, void* device_buffer, size_t size) override;
    bool write_buffer(void* device_buffer, const void* host_ptr, size_t size) override;

    void* allocate_buffer(size_t size, bool host_access = false) override;
    void free_buffer(void* buffer) override;

    uint32_t get_max_workgroup_size() const override { return max_threads_per_block_; }
    uint64_t get_max_global_size() const override { return max_grid_size_; }
    size_t get_device_memory() const override { return device_memory_; }
    std::string get_device_name() const override { return device_name_; }

private:
    int device_id_ = -1;
    cudaDeviceProp device_prop_;
    std::string device_name_;
    uint32_t max_threads_per_block_ = 256;
    uint64_t max_grid_size_ = 0;
    size_t device_memory_ = 0;

    CUfunction kernel_ = nullptr;
    CUmodule module_ = nullptr;
    std::vector<void*> kernel_args_;
    std::vector<CUdeviceptr> buffers_;

    void check_cuda_error(cudaError_t err, const char* msg);
    void check_driver_error(CUresult err, const char* msg);
};

} // namespace KracKer