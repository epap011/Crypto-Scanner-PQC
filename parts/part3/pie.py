import matplotlib.pyplot as plt

# Data for the budget allocation
phases = ["Phase 1: Immediate Fixes", "Phase 2: Intermediate Remediations", "Phase 3: PQC Migration"]
budgets = [1500, 3000, 4500] 

# Create the pie chart
fig, ax = plt.subplots()
ax.pie(budgets, labels=phases, autopct='%1.1f%%', startangle=90)
ax.axis('equal')  # Equal aspect ratio ensures the pie is circular.

# Add a title
plt.title("Cryptographic Migration Budget Allocation")

# Show the chart
plt.show()
