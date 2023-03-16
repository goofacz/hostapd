#ifndef LUA_EXT_H
#define LUA_EXT_H

struct lua_ext;

struct lua_ext*
lua_ext_create(void);

void
lua_ext_free(struct lua_ext *l);

int
lua_ext_eval(struct lua_ext *l, const char *prog, char *buf, size_t buflen);

#ifdef CONFIG_WPS
int
lua_ext_wps_lookup_cred(struct lua_ext *l, const char *bss_name, const u8 *mac_addr,
							char **psk);
#endif /* CONFIG_WPS */

#endif /* LUA_EXT_H */
