# TODO (DRAFT)

## Part2
i think we are good.

## Part4

1. Maybe more options for correcting vulnerabilities
2. Check if they are working all correct (i think one i tested didnt actually fixed the vulnerability)
3. Some recommendations by gpt (not all are correct):

1. **Integration of Risk Prioritization**:
   - While your implementation handles fixes, the prioritization of vulnerabilities (e.g., based on Mosca’s inequality) isn't explicitly reflected in the GUI or logic.
   - Suggestion: Add a column or visual indicator in the GUI for prioritization (e.g., "Critical Fix Needed," "Urgent for Quantum Readiness").

2. **Simulation Metrics and Statistics**:
   - The project description specifies that the simulator should provide comprehensive statistics, such as:
     - Number of vulnerabilities fixed automatically.
     - Number of files requiring manual intervention.
     - Overall improvement in the cryptographic posture.
   - Suggestion: Include a section in the GUI for displaying post-simulation statistics in a summary format.

3. **Compliance Monitoring**:
   - The project emphasizes compliance with standards like NIST SP 800-57 and SP 800-131A.
   - Suggestion: Add a compliance check to validate fixes against these standards and flag any issues.

4. **Simulation Scenarios**:
   - While fixes are implemented, there’s no explicit simulation to show the "before" and "after" states dynamically (e.g., viewing vulnerabilities fixed vs. unresolved in real-time).
   - Suggestion: Extend the GUI to include a "Simulation Mode" to showcase changes applied and remaining vulnerabilities interactively.

5. **Dynamic Switching and Transition Strategies**:
   - The project highlights the need to dynamically demonstrate cryptographic agility, including fallback strategies if certain algorithms are deprecated.
   - Suggestion: Implement fallback mechanisms or simulations to demonstrate agility beyond static replacements (e.g., switching to a backup algorithm if a fix fails).

6. **Visualization**:
   - The project suggests visualizing data and simulation results (e.g., graphs or charts) for better comprehension.
   - Suggestion: Use libraries like `matplotlib` or `tkinter.Canvas` to display bar charts or pie charts representing vulnerabilities and their fixes.

7. **Export Functionality for Results**:
   - The simulator should allow users to export simulation results (e.g., fixes applied, unresolved issues) to CSV or other formats.
   - Suggestion: Extend the export functionality to include post-simulation results.

8. **Integration of Phased Migration**:
   - The project emphasizes a structured migration process for cryptographic agility, including steps like testing, deployment, and monitoring.
   - Suggestion: Add a feature in the GUI to outline and track migration phases for individual findings or entire files.

---
