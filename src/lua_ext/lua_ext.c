#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "utils/os.h"
#include "utils/common.h"
#include "lua_ext.h"

struct lua_ext {
	lua_State *L;
};

static void *
lua_ext_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (nsize == 0) {
		os_free(ptr);
		return NULL;
	}

	return os_realloc(ptr, nsize);
}

struct lua_ext*
lua_ext_create(void)
{
	struct lua_ext *l = os_zalloc(sizeof(*l));
	if (l == NULL)
		return NULL;

	l->L = lua_newstate(lua_ext_alloc, NULL);
	luaL_openlibs(l->L);

	return l;
}

void
lua_ext_free(struct lua_ext *l)
{
	if (l == NULL)
		return;

	lua_close(l->L);
	os_free(l);
}

int
lua_ext_eval(struct lua_ext *l, const char *prog, char *buf, size_t buflen)
{
	const int load_res = luaL_loadstring(l->L, prog);
	if (load_res != LUA_OK) {
		const char *err = lua_tostring(l->L, -1);
		const int reply_len = os_snprintf(buf, buflen, "FAIL-LOAD %s\n", err);
		lua_pop(l->L, 1);
		return reply_len;
	}

	const int call_res = lua_pcall(l->L, 0, 1, 0);
	if (call_res != LUA_OK) {
		const char *err = lua_tostring(l->L, -1);
		const int reply_len = os_snprintf(buf, buflen, "FAIL-CALL %s\n", err);
		lua_pop(l->L, 1);
		return reply_len;
	}

	const int nil_res = lua_isnil(l->L, -1);
	if (nil_res != 0)
		return os_snprintf(buf, buflen, "OK\n");

	const char *res = lua_tostring(l->L, -1);
	if (res == NULL)
		return os_snprintf(buf, buflen, "FAILED-RES\n");

	const int reply_len = os_snprintf(buf, buflen, "OK-RES %s\n", res);
	lua_pop(l->L, 1);
	return reply_len;
}

#ifdef CONFIG_WPS
int
lua_ext_wps_lookup_cred(struct lua_ext *l, const char *bss_name, const u8 *mac_addr,
							char **psk)
{
	char mac_addr_buf[20];

	os_snprintf(mac_addr_buf, sizeof(mac_addr_buf), MACSTR, MAC2STR(mac_addr));

	lua_getglobal(l->L, "wps_lookup_cred");
	const int func_exists = lua_isfunction(l->L, -1);
	if (!func_exists) {
		wpa_printf(MSG_DEBUG, "WPS: Lua ext not defined");
		lua_pop(l->L, 1);
		return 0;
	}

	lua_pushstring(l->L, bss_name);
	lua_pushstring(l->L, mac_addr_buf);

	const int call_res = lua_pcall(l->L, 2, 1, 0);
	if (call_res != LUA_OK) {
		const char * err_msg = lua_isstring(l->L, -1) ?
			lua_tostring(l->L, -1) :
			"unknown error";

		wpa_printf(MSG_DEBUG, "WPS: Failed to lookup creds from Lua ext: %s",
			err_msg);

		lua_pop(l->L, 1);
		return 0;
	}

	const int ok_psk = lua_isstring(l->L, -1);
	if (ok_psk != 0)
		*psk = os_strdup(lua_tostring(l->L, -1));
	else
		wpa_printf(MSG_DEBUG, "WPS: No appropriate creds returned by Lua ext");

	lua_pop(l->L, 1);
	return ok_psk;
}
#endif /* CONFIG_WPS */
