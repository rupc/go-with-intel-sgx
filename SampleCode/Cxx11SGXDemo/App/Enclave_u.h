#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_lambdas_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_auto_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_decltype_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_strongly_typed_enum_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_range_based_for_loops_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_static_assert_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_virtual_function_control_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_delegating_constructors_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_std_function_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_cxx11_algorithms_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_variadic_templates_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_SFINAE_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_initializer_list_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_rvalue_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_nullptr_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_enum_class_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_new_container_classes_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_tuple_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_shared_ptr_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_atomic_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_mutex_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_print_final_value_mutex_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_mutex_demo_no_protection(sgx_enclave_id_t eid);
sgx_status_t ecall_print_final_value_no_protection(sgx_enclave_id_t eid);
sgx_status_t ecall_condition_variable_run(sgx_enclave_id_t eid);
sgx_status_t ecall_condition_variable_load(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
