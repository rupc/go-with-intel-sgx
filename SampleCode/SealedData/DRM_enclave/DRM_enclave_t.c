#include "DRM_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_create_sealed_policy_t {
	uint32_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_create_sealed_policy_t;

typedef struct ms_perform_sealed_policy_t {
	uint32_t ms_retval;
	const uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_perform_sealed_policy_t;

typedef struct ms_update_sealed_policy_t {
	uint32_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_update_sealed_policy_t;

typedef struct ms_delete_sealed_policy_t {
	uint32_t ms_retval;
	const uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_delete_sealed_policy_t;

typedef struct ms_create_time_based_policy_t {
	uint32_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_create_time_based_policy_t;

typedef struct ms_perform_time_based_policy_t {
	uint32_t ms_retval;
	const uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_perform_time_based_policy_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

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

static sgx_status_t SGX_CDECL sgx_create_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_create_sealed_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_create_sealed_policy_t* ms = SGX_CAST(ms_create_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_log = (uint8_t*)malloc(_len_sealed_log)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_log, 0, _len_sealed_log);
	}

	ms->ms_retval = create_sealed_policy(_in_sealed_log, _tmp_sealed_log_size);
	if (_in_sealed_log) {
		if (memcpy_s(_tmp_sealed_log, _len_sealed_log, _in_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

static sgx_status_t SGX_CDECL sgx_perform_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_perform_sealed_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_perform_sealed_policy_t* ms = SGX_CAST(ms_perform_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_log, _len_sealed_log, _tmp_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = perform_sealed_policy((const uint8_t*)_in_sealed_log, _tmp_sealed_log_size);

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

static sgx_status_t SGX_CDECL sgx_update_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_update_sealed_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_update_sealed_policy_t* ms = SGX_CAST(ms_update_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_log, _len_sealed_log, _tmp_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = update_sealed_policy(_in_sealed_log, _tmp_sealed_log_size);
	if (_in_sealed_log) {
		if (memcpy_s(_tmp_sealed_log, _len_sealed_log, _in_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

static sgx_status_t SGX_CDECL sgx_delete_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_delete_sealed_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_delete_sealed_policy_t* ms = SGX_CAST(ms_delete_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_log, _len_sealed_log, _tmp_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = delete_sealed_policy((const uint8_t*)_in_sealed_log, _tmp_sealed_log_size);

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

static sgx_status_t SGX_CDECL sgx_create_time_based_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_create_time_based_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_create_time_based_policy_t* ms = SGX_CAST(ms_create_time_based_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_log = (uint8_t*)malloc(_len_sealed_log)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_log, 0, _len_sealed_log);
	}

	ms->ms_retval = create_time_based_policy(_in_sealed_log, _tmp_sealed_log_size);
	if (_in_sealed_log) {
		if (memcpy_s(_tmp_sealed_log, _len_sealed_log, _in_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

static sgx_status_t SGX_CDECL sgx_perform_time_based_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_perform_time_based_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_perform_time_based_policy_t* ms = SGX_CAST(ms_perform_time_based_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ( _len_sealed_log % sizeof(*_tmp_sealed_log) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_log, _len_sealed_log, _tmp_sealed_log, _len_sealed_log)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = perform_time_based_policy((const uint8_t*)_in_sealed_log, _tmp_sealed_log_size);

err:
	if (_in_sealed_log) free(_in_sealed_log);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_create_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_perform_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_update_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_delete_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_create_time_based_policy, 0},
		{(void*)(uintptr_t)sgx_perform_time_based_policy, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][6];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;

	CHECK_ENCLAVE_POINTER(sid, _len_sid);
	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sid != NULL) ? _len_sid : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg1 != NULL) ? _len_dh_msg1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));
	ocalloc_size -= sizeof(ms_create_session_ocall_t);

	if (sid != NULL) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp_sid = __tmp;
		if (_len_sid % sizeof(*sid) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
		ocalloc_size -= _len_sid;
	} else {
		ms->ms_sid = NULL;
	}
	
	if (dh_msg1 != NULL) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		if (_len_dh_msg1 % sizeof(*dh_msg1) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sid) {
			if (memcpy_s((void*)sid, _len_sid, __tmp_sid, _len_sid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg2 != NULL) ? _len_dh_msg2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg3 != NULL) ? _len_dh_msg3 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	ms->ms_sid = sid;
	if (dh_msg2 != NULL) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		if (_len_dh_msg2 % sizeof(*dh_msg2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		if (_len_dh_msg3 % sizeof(*dh_msg3) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));
	ocalloc_size -= sizeof(ms_close_session_ocall_t);

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;

	CHECK_ENCLAVE_POINTER(pse_message_req, _len_pse_message_req);
	CHECK_ENCLAVE_POINTER(pse_message_resp, _len_pse_message_resp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_req != NULL) ? _len_pse_message_req : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_resp != NULL) ? _len_pse_message_resp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));
	ocalloc_size -= sizeof(ms_invoke_service_ocall_t);

	if (pse_message_req != NULL) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		if (_len_pse_message_req % sizeof(*pse_message_req) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pse_message_req, _len_pse_message_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		ocalloc_size -= _len_pse_message_req;
	} else {
		ms->ms_pse_message_req = NULL;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp_pse_message_resp = __tmp;
		if (_len_pse_message_resp % sizeof(*pse_message_resp) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		ocalloc_size -= _len_pse_message_resp;
	} else {
		ms->ms_pse_message_resp = NULL;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pse_message_resp) {
			if (memcpy_s((void*)pse_message_resp, _len_pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

