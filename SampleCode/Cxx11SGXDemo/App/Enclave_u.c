#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_lambdas_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_auto_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_decltype_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_strongly_typed_enum_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_range_based_for_loops_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_static_assert_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_virtual_function_control_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_delegating_constructors_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_std_function_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_cxx11_algorithms_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_variadic_templates_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_SFINAE_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_initializer_list_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_rvalue_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_nullptr_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_enum_class_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_new_container_classes_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_tuple_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_shared_ptr_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_atomic_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_mutex_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_print_final_value_mutex_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_mutex_demo_no_protection(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_print_final_value_no_protection(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_condition_variable_run(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_condition_variable_load(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, NULL);
	return status;
}

