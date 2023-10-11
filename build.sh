# Remove old build files and make new build directory
rm -rf build
mkdir -p build

if [ -v LIBOQS_ROOT ] && [ -e $LIBOQS_ROOT ]; then
    echo "liboqs directory already exists, skipping cloning"; \
else \
    git clone -b main https://github.com/open-quantum-safe/liboqs.git; \
    export LIBOQS_ROOT=$(pwd)/liboqs; \
fi

cmake -GNinja -B $LIBOQS_ROOT/build liboqs && ninja -j $(nproc) -C $LIBOQS_ROOT/build

# Set the path to the liboqs root directory
RESULT_DIR="src/oqspython"

# Compile the C++ wrapper
swig -python -c++ -o ./build/oqspython_wrap.cxx -I$LIBOQS_ROOT/build/include oqspython.i

# Compile the C++ wrapper and link it with liboqs
g++ -std=c++20 -O2 -fPIC -I$LIBOQS_ROOT/build/include $(python-config --cflags) -c ./build/oqspython_wrap.cxx -o ./build/oqspython_wrap.o
# Manual working version: g++ -std=c++20 -O2 -fPIC -I$LIBOQS_ROOT/build/include -I/Users/petr/.pyenv/versions/3.11.5/include/python3.11 -c ./build/oqspython_wrap.cxx -o ./build/oqspython_wrap.o

# Link the C++ wrapper with liboqs and Python+OpenSSL+Intl
g++ -std=c++20 -shared ./build/oqspython_wrap.o -L$LIBOQS_ROOT/build/lib -loqs -L$(python-config --prefix)/lib -l$(ls $(python-config --prefix)/lib | grep -o 'python[0-9]\+\.[0-9]\+' | tail -1) -lssl -lcrypto -o ./build/_oqspython.so
# Manual working version: g++ -std=c++20 -shared ./build/oqspython_wrap.o -L$LIBOQS_ROOT/build/lib -loqs -L/Users/petr/.pyenv/versions/3.11.5/lib -lpython3.11 -L/opt/homebrew/lib -lintl -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto -o ./build/_oqspython.so

# Copy the Python wrapper and the compiled C++ wrapper to the desired location
rm -rf $RESULT_DIR
mkdir -p $RESULT_DIR
cp ./build/oqspython.py $RESULT_DIR/oqspython.py
cp ./build/_oqspython.so $RESULT_DIR/_oqspython.so
touch $RESULT_DIR/__init__.py

hatch build
# pip install --upgrade --force-reinstall dist/oqspython-*.whl
