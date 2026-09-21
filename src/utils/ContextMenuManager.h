#pragma once

#include <QString>

namespace verax {

class ContextMenuManager {
public:
    static bool isEnabled();
    static bool setEnabled(bool enable);
};

} // namespace verax
