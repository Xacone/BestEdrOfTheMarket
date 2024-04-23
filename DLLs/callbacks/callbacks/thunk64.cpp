#include "pch.h"
#include "thunk64.h"
#if __has_include("thunk64.g.cpp")
#include "thunk64.g.cpp"
#endif

namespace winrt::callbacks::implementation
{
    int32_t thunk64::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void thunk64::MyProperty(int32_t /*value*/)
    {
        throw hresult_not_implemented();
    }
}
