%module cdipc
%{
    #include <cdipc/utils/cd_time.h>
    #include <cdipc/utils/cd_utils.h>
    #include <cdipc/utils/rlist.h>
    #include <cdipc/cdipc.h>
    #include "../swig_helper.h"
%}


%include "/usr/include/bits/types/struct_timespec.h"
%include "../../cdipc/utils/cd_time.h"
%include "../../cdipc/cdipc.h"


%typemap(in) (char *data, int size)
{
    if (!PyString_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "String value required");
        return NULL;
    }

    $1 = PyString_AsString($input);
    $2 = PyString_Size($input);
}

%typemap(out) swig_string_data_t
{
    $result = PyBytes_FromStringAndSize($1.data, $1.size);
    //free($1.data);
}

%include "./swig_helper.h"

