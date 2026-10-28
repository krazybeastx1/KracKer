#include "KracKer/opencl_context.hpp"
#include <iostream>
#include <sstream>

namespace KracKer {

void OpenCLContext::check_cl_error(cl_int err, const char* msg) {
    if (err != CL_SUCCESS) {
        std::cerr << "OpenCL Error: " << msg << " (" << err << ")" << std::endl;
    }
}

bool OpenCLContext::initialize(uint32_t device_id) {
    cl_int err;

    // Get platform
    cl_uint num_platforms;
    err = clGetPlatformIDs(0, nullptr, &num_platforms);
    check_cl_error(err, "clGetPlatformIDs");
    if (num_platforms == 0) return false;

    std::vector<cl_platform_id> platforms(num_platforms);
    err = clGetPlatformIDs(num_platforms, platforms.data(), nullptr);
    check_cl_error(err, "clGetPlatformIDs");

    // Use first platform
    platform_ = platforms[0];

    // Get devices
    cl_uint num_devices;
    err = clGetDeviceIDs(platform_, CL_DEVICE_TYPE_GPU, 0, nullptr, &num_devices);
    check_cl_error(err, "clGetDeviceIDs");
    if (device_id >= num_devices) return false;

    std::vector<cl_device_id> devices(num_devices);
    err = clGetDeviceIDs(platform_, CL_DEVICE_TYPE_GPU, num_devices, devices.data(), nullptr);
    check_cl_error(err, "clGetDeviceIDs");

    device_ = devices[device_id];

    // Get device info
    char name[128];
    clGetDeviceInfo(device_, CL_DEVICE_NAME, sizeof(name), name, nullptr);
    device_name_ = name;

    size_t max_wg_size;
    clGetDeviceInfo(device_, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_wg_size), &max_wg_size, nullptr);
    max_workgroup_size_ = static_cast<uint32_t>(max_wg_size);

    size_t max_mem;
    clGetDeviceInfo(device_, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(max_mem), &max_mem, nullptr);
    device_memory_ = max_mem;

    // Create context
    context_ = clCreateContext(nullptr, 1, &device_, nullptr, nullptr, &err);
    check_cl_error(err, "clCreateContext");

    // Create command queue
    queue_ = clCreateCommandQueue(context_, device_, 0, &err);
    check_cl_error(err, "clCreateCommandQueue");

    return true;
}

void OpenCLContext::shutdown() {
    for (cl_mem buf : buffers_) {
        clReleaseMemObject(buf);
    }
    buffers_.clear();

    if (kernel_) clReleaseKernel(kernel_);
    if (program_) clReleaseProgram(program_);
    if (queue_) clReleaseCommandQueue(queue_);
    if (context_) clReleaseContext(context_);

    kernel_ = nullptr;
    program_ = nullptr;
    queue_ = nullptr;
    context_ = nullptr;
    device_ = nullptr;
    platform_ = nullptr;
}

bool OpenCLContext::compile_kernel(const std::string& source, const std::string& kernel_name) {
    cl_int err;

    const char* src = source.c_str();
    program_ = clCreateProgramWithSource(context_, 1, &src, nullptr, &err);
    check_cl_error(err, "clCreateProgramWithSource");

    err = clBuildProgram(program_, 1, &device_, "-cl-std=CL1.2", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Get build log
        size_t log_size;
        clGetProgramBuildInfo(program_, device_, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::vector<char> log(log_size);
        clGetProgramBuildInfo(program_, device_, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::cerr << "Build log:\n" << log.data() << std::endl;
        check_cl_error(err, "clBuildProgram");
        return false;
    }

    kernel_ = clCreateKernel(program_, kernel_name.c_str(), &err);
    check_cl_error(err, "clCreateKernel");

    return true;
}

bool OpenCLContext::set_kernel_arg(uint32_t index, const void* data, size_t size) {
    if (!kernel_) return false;
    cl_int err = clSetKernelArg(kernel_, index, size, data);
    check_cl_error(err, "clSetKernelArg");
    return err == CL_SUCCESS;
}

bool OpenCLContext::set_buffer_arg(uint32_t index, void* buffer, size_t size) {
    return set_kernel_arg(index, &buffer, sizeof(cl_mem));
}

bool OpenCLContext::execute_kernel(uint64_t global_size, uint64_t local_size) {
    if (!kernel_ || !queue_) return false;

    size_t global = static_cast<size_t>(global_size);
    size_t local = local_size > 0 ? static_cast<size_t>(local_size) : max_workgroup_size_;

    cl_int err = clEnqueueNDRangeKernel(queue_, kernel_, 1, nullptr, &global, &local, 0, nullptr, nullptr);
    check_cl_error(err, "clEnqueueNDRangeKernel");

    clFinish(queue_);
    return err == CL_SUCCESS;
}

bool OpenCLContext::read_buffer(void* host_ptr, void* device_buffer, size_t size) {
    if (!queue_) return false;
    cl_int err = clEnqueueReadBuffer(queue_, static_cast<cl_mem>(device_buffer), CL_TRUE, 0, size, host_ptr, 0, nullptr, nullptr);
    check_cl_error(err, "clEnqueueReadBuffer");
    return err == CL_SUCCESS;
}

bool OpenCLContext::write_buffer(void* device_buffer, const void* host_ptr, size_t size) {
    if (!queue_) return false;
    cl_int err = clEnqueueWriteBuffer(queue_, static_cast<cl_mem>(device_buffer), CL_TRUE, 0, size, host_ptr, 0, nullptr, nullptr);
    check_cl_error(err, "clEnqueueWriteBuffer");
    return err == CL_SUCCESS;
}

void* OpenCLContext::allocate_buffer(size_t size, bool host_access) {
    if (!context_) return nullptr;

    cl_mem_flags flags = CL_MEM_READ_WRITE;
    if (host_access) flags |= CL_MEM_ALLOC_HOST_PTR;

    cl_int err;
    cl_mem buffer = clCreateBuffer(context_, flags, size, nullptr, &err);
    check_cl_error(err, "clCreateBuffer");

    if (err == CL_SUCCESS) {
        buffers_.push_back(buffer);
        return buffer;
    }
    return nullptr;
}

void OpenCLContext::free_buffer(void* buffer) {
    if (!buffer) return;
    auto it = std::find(buffers_.begin(), buffers_.end(), buffer);
    if (it != buffers_.end()) {
        clReleaseMemObject(*it);
        buffers_.erase(it);
    }
}

} // namespace KracKer