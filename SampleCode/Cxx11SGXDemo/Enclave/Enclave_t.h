#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_lambdas_demo(void);
void ecall_auto_demo(void);
void ecall_decltype_demo(void);
void ecall_strongly_typed_enum_demo(void);
void ecall_range_based_for_loops_demo(void);
void ecall_static_assert_demo(void);
void ecall_virtual_function_control_demo(void);
void ecall_delegating_constructors_demo(void);
void ecall_std_function_demo(void);
void ecall_cxx11_algorithms_demo(void);
void ecall_variadic_templates_demo(void);
void ecall_SFINAE_demo(void);
void ecall_initializer_list_demo(void);
void ecall_rvalue_demo(void);
void ecall_nullptr_demo(void);
void ecall_enum_class_demo(void);
void ecall_new_container_classes_demo(void);
void ecall_tuple_demo(void);
void ecall_shared_ptr_demo(void);
void ecall_atomic_demo(void);
void ecall_mutex_demo(void);
void ecall_print_final_value_mutex_demo(void);
void ecall_mutex_demo_no_protection(void);
void ecall_print_final_value_no_protection(void);
void ecall_condition_variable_run(void);
void ecall_condition_variable_load(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
