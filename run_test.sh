
mkdir -p bin

# Compile Spine compiler
gcc src/main.c -o bin/spine

# Use Spine compiler to create a binary
if [ $# -eq 0 ]
then
	echo "Error: Expected a Spine program as first argument."
	echo "Try \"104p10p\" for example (it should print h or something)."
fi
./bin/spine "$1"

# Run the binary produced by the Spine compiler
chmod +x bin/jaaj
./bin/jaaj
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]
then
	echo "Binary exit code: $EXIT_CODE"
fi
