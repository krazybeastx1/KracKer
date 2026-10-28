#include "KracKer/cuda_context.hpp"
#include <cuda.h>
#include <iostream>
#include <sstream>

namespace KracKer {

void CUDAContext::check_cuda_error(cudaError_t err, const char* msg) {
    if (err != cudaSuccess) {
        std::cerr << "CUDA Error: " << msg << " (" << cudaGetErrorString(err) << ")" << std::endl;
    }
}

void CUDAContext::check_driver_error(CUresult err, const char* msg) {
    if (err != CUDA_SUCCESS) {
        const char* err_str;
        cuGetErrorString(err, &err_str);
        std::cerr << "CUDA Driver Error: " << msg << " (" << err_str << ")" << std::endl;
    }
}

bool CUDAContext::initialize(uint32_t device_id) {
    device_id_ = device_id;

    cudaError_t err = cudaSetDevice(device_id_);
    check_cuda_error(err, "cudaSetDevice");
    if (err != cudaSuccess) return false;

    err = cudaGetDeviceProperties(&device_prop_, device_id_);
    check_cuda_error(err, "cudaGetDeviceProperties");
    if (err != cudaSuccess) return false;

    device_name_ = device_prop_.name;
    max_threads_per_block_ = device_prop_.maxThreadsPerBlock;
    max_grid_size_ = device_prop_.maxGridSize[0];
    device_memory_ = device_prop_.totalGlobalMem;

    // Initialize driver API for module loading
    CUresult drv_err = cuInit(0);
    check_driver_error(drv_err, "cuInit");

    CUdevice cu_device;
    drv_err = cuDeviceGet(&cu_device, device_id_);
    check_driver_error(drv_err, "cuDeviceGet");

    CUcontext context;
    drv_err = cuCtxCreate(&context, 0, cu_device);
    check_driver_error(drv_err, "cuCtxCreate");

    return true;
}

void CUDAContext::shutdown() {
    for (CUdeviceptr buf : buffers_) {
        cuMemFree(buf);
    }
    buffers_.clear();

    if (module_) {
        cuModuleUnload(module_);
        module_ = nullptr;
    }
    kernel_ = nullptr;

    cuCtxDestroy(nullptr);
    device_id_ = -1;
}

bool CUDAContext::compile_kernel(const std::string& source, const std::string& kernel_name) {
    // Compile with nvrtc or use precompiled PTX
    // For simplicity, we'll use the driver API with PTX
    // In production, you'd compile with nvrtc at runtime or precompile to PTX

    std::string ptx_source = source; // Assume PTX source is passed

    CUresult err = cuModuleLoadData(&module_, ptx_source.c_str());
    check_driver_error(err, "cuModuleLoadData");
    if (err != CUDA_SUCCESS) return false;

    err = cuModuleGetFunction(&kernel_, module_, kernel_name.c_str());
    check_driver_error(err, "cuModuleGetFunction");
    if (err != CUDA_SUCCESS) return false;

    kernel_args_.clear();
    return true;
}

bool CUDAContext::set_kernel_arg(uint32_t index, const void* data, size_t size) {
    if (index >= kernel_args_.size()) {
        kernel_args_.resize(index + 1, nullptr);
    }
    kernel_args_[index] = const_cast<void*>(data);
    return true;
}

bool CUDAContext::set_buffer_arg(uint32_t index, void* buffer, size_t size) {
    return set_kernel_arg(index, &buffer, sizeof(CUdeviceptr));
}

bool CUDAContext::execute_kernel(uint64_t global_size, uint64_t local_size) {
    if (!kernel_) return false;

    void** args = kernel_args_.data();
    int num_args = kernel_args_.size();

    CUresult err = cuLaunchKernel(
        kernel_,
        global_size / local_size, 1, 1,  // grid dim
        local_size, 1, 1,                // block dim
        0, nullptr,                      // shared mem, stream
        args, nullptr                    // args, extra
    );
    check_driver_error(err, "cuLaunchKernel");

    cuCtxSynchronize();
    return err == CUDA_SUCCESS;
}

bool CUDAContext::read_buffer(void* host_ptr, void* device_buffer, size_t size) {
    CUresult err = cuMemcpyDtoH(host_ptr, reinterpret_cast<CUdeviceptr>(device_buffer), size);
    check_driver_error(err, "cuMemcpyDtoH");
    return err == CUDA_SUCCESS;
}

bool CUDAContext::write_buffer(void* device_buffer, const void* host_ptr, size_t size) {
    CUresult err = cuMemcpyHtoD(reinterpret_cast<CUdeviceptr>(device_buffer), host_ptr, size);
    check_driver_error(err, "cuMemcpyHtoD");
    return err == CUDA_SUCCESS;
}

void* CUDAContext::allocate_buffer(size_t size, bool host_access) {
    CUdeviceptr buffer;
    CUresult err;

    if (host_access) {
        err = cuMemAllocHost(reinterpret_cast<void**>(&buffer), size);
    } else {
        err = cuMemAlloc(&buffer, size);
    }

    check_driver_error(err, "cuMemAlloc");
    if (err == CUDA_SUCCESS) {
        buffers_.push_back(reinterpret_cast<void*>(buffer));
        return reinterpret_cast<void*>(buffer);
    }
    return nullptr;
}

void CUDAContext::free_buffer(void* buffer) {
    if (!buffer) return;
    auto it = std::find(buffers_.begin(), buffers_.end(), buffer);
    if (it != buffers_.end()) {
        cuMemFree(reinterpret_cast<CUdeviceptr>(buffer));
        buffers_.erase(it);
    }
}

} // namespace KracKer