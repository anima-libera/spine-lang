
# Compile the Spine compiler,
# then invoke it to compile some Spine code,
# then invoke the compiled Spine program.

# 2 aguments are fowarded to the spine compiler

mkdir -p bin

# Compile Spine compiler
gcc src/main.c -o bin/spine -Os

# Use Spine compiler to create a binary
if [ $# -eq 0 ]
then
	echo "Error: Expected a Spine program as first argument."
	echo "Try \"104p10p\" for example (it should print h or something)."
fi
./bin/spine -f src/stdlib.spn "$@"

# Run the binary produced by the Spine compiler
chmod +x bin/jaaj
./bin/jaaj
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]
then
	echo "Binary exit code: $EXIT_CODE"
fi
