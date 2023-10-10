# Remove old build files and make new build directory
rm -rf build
mkdir -p build

if [ -e "liboqs" ]; then
    echo "liboqs directory already exists, skipping cloning"; \
else \
    git submodule update --init --remote --recursive; \
fi

cmake -GNinja -B liboqs/build liboqs && ninja -j $(nproc) -C liboqs/build

# Set the path to the liboqs root directory
LIBOQS_ROOT_DIR="liboqs"
RESULT_DIR="src/oqspython"

# Compile the C++ wrapper
swig -python -c++ -o ./build/oqspython_wrap.cxx -I$LIBOQS_ROOT_DIR/build/include oqspython.i

# Compile the C++ wrapper and link it with liboqs
g++ -std=c++20 -O2 -fPIC -I$LIBOQS_ROOT_DIR/build/include $(python-config --cflags) -c ./build/oqspython_wrap.cxx -o ./build/oqspython_wrap.o
# Manual working version: g++ -std=c++20 -O2 -fPIC -I$LIBOQS_ROOT_DIR/build/include -I/Users/petr/.pyenv/versions/3.11.5/include/python3.11 -c ./build/oqspython_wrap.cxx -o ./build/oqspython_wrap.o

# Link the C++ wrapper with liboqs and Python+OpenSSL+Intl
g++ -std=c++20 -shared ./build/oqspython_wrap.o -L$LIBOQS_ROOT_DIR/build/lib -loqs -L$(python-config --prefix)/lib -l$(ls $(python-config --prefix)/lib | grep -o 'python[0-9]\+\.[0-9]\+' | tail -1) -lssl -lcrypto -o ./build/_oqspython.so
# Manual working version: g++ -std=c++20 -shared ./build/oqspython_wrap.o -L$LIBOQS_ROOT_DIR/build/lib -loqs -L/Users/petr/.pyenv/versions/3.11.5/lib -lpython3.11 -L/opt/homebrew/lib -lintl -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto -o ./build/_oqspython.so

# Copy the Python wrapper and the compiled C++ wrapper to the desired location
rm -rf $RESULT_DIR
mkdir -p $RESULT_DIR
cp ./build/oqspython.py $RESULT_DIR/oqspython.py
cp ./build/_oqspython.so $RESULT_DIR/_oqspython.so
touch $RESULT_DIR/__init__.py

hatch build
# pip install --upgrade --force-reinstall dist/oqspython-*.whl
