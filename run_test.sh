
# Compile Spine compiler
gcc src/main.c -o bin/spine

# Use Spine compiler to create a binary
./bin/spine

# Run the binary produced by the Spine compiler
chmod +x local/jaaj
./local/jaaj
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]
then
	echo "Binary exit code: $EXIT_CODE"
fi
