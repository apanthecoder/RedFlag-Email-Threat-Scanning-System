import { createContext, useContext } from "react";

/** Whether the report section around a component has scrolled into view.
 *
 * ReportSection and CollapsiblePanel provide it. Lists inside read it so
 * their items animate in when the section is reached, not unseen on page
 * load. Defaults to true, so a component outside a section just shows.
 */
export const SectionShownContext = createContext(true);

export default function useSectionShown() {
  return useContext(SectionShownContext);
}
