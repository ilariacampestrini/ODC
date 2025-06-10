import angr
import claripy


class Skip(angr.SimProcedure):
    def run(self):
        return 1
    
class Len(angr.SimProcedure):
    def run(self):
        return 49

binary_path = 'notsohandy'

project = angr.Project(binary_path, auto_load_libs=False)
flag_len = 49
base = 0x400000
find = 0x1422+base
avoid = [0x12A5+base, 0x13DC+base, 0x1433+base]

# Skip useless time wasting instruction
project.hook_symbol('xhashe_slow', Skip())

# Replace every length with 49, it's always the correct value, no need to calculate
project.hook_symbol('strlen', Len(), replace=True)

input_flag = claripy.BVS('flag', 8 * flag_len)
state = project.factory.entry_state(args=[binary_path, input_flag], add_options={angr.options.LAZY_SOLVES})

for byte in input_flag.chop(8):
    state.add_constraints(byte > 64)
    state.add_constraints(byte < 0x7f)

state.add_constraints(input_flag.chop(8)[0] == ord('f'))
state.add_constraints(input_flag.chop(8)[1] == ord('l'))
state.add_constraints(input_flag.chop(8)[2] == ord('a'))
state.add_constraints(input_flag.chop(8)[3] == ord('g'))
state.add_constraints(input_flag.chop(8)[4] == ord('{'))
state.add_constraints(input_flag.chop(8)[flag_len-1] == ord('}'))
    
simulation = project.factory.simulation_manager(state)
simulation.explore(find=find , avoid=avoid)

if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.solver.eval(input_flag, cast_to=bytes)
    print("Correct flag: ", solution)
else:
    print('NO solution\n')