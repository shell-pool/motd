//
// You can test that this builds and examine the exported symbols with
//
// ```
// gcc -Wl,--version-script=./motd/src/pam_motd_overlay_versions.map -shared -fPIC ./motd/src/pam_motd_overlay.c -o /tmp/pam_motd_overlay.so
// nm -D /tmp/pam_motd_overlay.so
// ```
//

#include <pwd.h>
#include <security/_pam_types.h>
#include <stdio.h>
#include <sys/types.h>

static struct passwd fake_passwd = {
  .pw_name = "",
  .pw_passwd = "",
  .pw_uid = 0,
  .pw_gid = 0,
  .pw_gecos = "",
  .pw_dir = "",
  .pw_shell = "",
};
struct passwd* pam_modutil_getpwnam(pam_handle_t *pamh, const char *user) {
  (void)pamh;
  (void)user;
  return &fake_passwd;
}
