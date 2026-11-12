package native

/*
#include "bridge.h"
#include <bee2/crypto/btok.h>
static int bee2go_pwd_transition(unsigned *pin, unsigned *auth, unsigned event) {
 btok_pwd_state s = {0}; s.pin = *pin; s.auth = *auth;
 int ok = btokPwdTransition(&s, (btok_pwd_event)event);
 *pin = s.pin; *auth = s.auth; return ok;
}
*/
import "C"

func BTOKPasswordTransition(pin, auth, event uint8) (uint8, uint8, bool, error) {
	if pin > 15 || auth > 3 || event > 8 {
		return pin, auth, false, invalid("btok password transition")
	}
	p, a := C.uint(pin), C.uint(auth)
	ok := C.bee2go_pwd_transition(&p, &a, C.uint(event)) != 0
	return uint8(p), uint8(a), ok, nil
}
