#pragma once

#include "thunk64.g.h"

namespace winrt::callbacks::implementation
{
    struct thunk64 : thunk64T<thunk64>
    {
        thunk64() = default;

        int32_t MyProperty();
        void MyProperty(int32_t value);
    };
}

namespace winrt::callbacks::factory_implementation
{
    struct thunk64 : thunk64T<thunk64, implementation::thunk64>
    {
    };
}
