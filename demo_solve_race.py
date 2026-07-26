from mambo import Mambo

# make solver & solve for license success function
solver = Mambo("examples/mambo_race_planner")
result = solver.solve_symbol("mambo_license_success")

print("License Recovery Results:")
print(result)
