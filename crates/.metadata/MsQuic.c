// force the return type to be long (for linux to work as well)
#define _HRESULT_DEFINED
#define HRESULT long
// TODO: typedef does not work. maybe scraper has special case for hresult
// typedef long QSTATUS;
// typedef QSTATUS HRESULT;
#include "msquic.h"