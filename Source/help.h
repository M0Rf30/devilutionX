/**
 * @file help.h
 *
 * Interface of the in-game help text.
 */
#pragma once

#include "engine.h"

namespace devilution {

extern bool helpflag;

void InitHelp();
void DrawHelp(const CelOutputBuffer &out);
void DisplayHelp();
void HelpScrollUp();
void HelpScrollDown();

} // namespace devilution
