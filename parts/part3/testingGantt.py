import plotly.express as px
from datetime import datetime

# Define the phases and their timelines
phases = [
    dict(Task="Phase 1: Immediate Fixes", Start='2025-01-01', Finish='2025-03-31',
         Description="Replace DES with AES-GCM, Replace MD5 with SHA-256, Migrate to TLS 1.3, etc."),
    dict(Task="Phase 2: Intermediate Remediations", Start='2025-04-01', Finish='2025-09-30',
         Description="Upgrade RSA-1024 to RSA-3072, Transition ECC to post-quantum, etc."),
    dict(Task="Phase 3: PQC Migration", Start='2025-10-01', Finish='2026-09-30',
         Description="Adopt Kyber, Adopt Dilithium, Roll out post-quantum cryptography, etc.")
]

# Create the Gantt chart
fig = px.timeline(phases, x_start="Start", x_end="Finish", y="Task", text="Description",
                  title="Cryptographic Migration Roadmap", labels={"Task": "Phases"})

# Apply single color and increase text font size
fig.update_traces(
    marker=dict(color='#636EFA', line=dict(color='black', width=1)),
    textfont=dict(size=16),  # Larger text font size
    textposition='inside'  # Text placed inside the bar
)

# Improve axis order and customize layout
fig.update_yaxes(categoryorder="total ascending")
fig.update_layout(
    title=dict(font=dict(size=24), x=0.5),  # Center-align title
    plot_bgcolor='white',  # Set background color to white
    xaxis_title="Timeline",
    yaxis_title="",
    xaxis=dict(showgrid=True, gridcolor='lightgray'),
    yaxis=dict(showgrid=False),
    font=dict(size=14)  # Default font size for other elements
)

# Show the chart
fig.show()
