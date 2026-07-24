from mambo import Mambo

solver = Mambo("examples/simple_crackme")
# To add any constraints you can just do this
# solver = Mambo("examples/simple_crackme", max_steps=1000)

# Solve using start and end addresses
result = solver.solve(0x40116b, 0x401156)
print(f"=== Solve 1 ===\n{result}")

# Omit the start address to begin at main
result = solver.solve(0x401156)
print(f"=== Solve 2 ===\n{result}")

# Symbol names can be used instead
result = solver.solve_symbol("main", "mambo_success")
print(f"=== Solve 3 ===\n{result}")

# Or if you just want the damn flag
result = solver.solve_symbol("mambo_success")
print(f"=== Solve 4 ===\n{result}")
