# Remove old build files and make new build directory
rm -rf build
mkdir -p build

# Set the path to the liboqs root directory
LIBOQS_ROOT_DIR="/Users/petr/Developer/Libraries/liboqs"
CP_PATH="/Users/petr/Developer/Repos/PQC-ESP32-Arduino/Connector/pqconnector/oqspython"

# Compile the C++ wrapper
swig -python -c++ -o ./build/oqspython_wrap.cxx -I$LIBOQS_ROOT_DIR/build/include oqspython.i

# Compile the C++ wrapper and link it with liboqs
g++ -std=c++20 -O2 -fPIC -I$LIBOQS_ROOT_DIR/build/include -I/Users/petr/.pyenv/versions/3.11.3/include/python3.11 -c ./build/oqspython_wrap.cxx -o ./build/oqspython_wrap.o

# Link the C++ wrapper with liboqs and Python+OpenSSL+Intl
g++ -std=c++20 -shared ./build/oqspython_wrap.o -L$LIBOQS_ROOT_DIR/build/lib -loqs -L/Users/petr/.pyenv/versions/3.11.3/lib -lpython3.11 -L/opt/homebrew/lib -lintl -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto -o ./build/_oqspython.so

# Copy the Python wrapper and the compiled C++ wrapper to the desired location
rm -r $CP_PATH/__pycache__
rm $CP_PATH/oqspython.py
rm $CP_PATH/_oqspython.so
cp ./build/oqspython.py $CP_PATH/oqspython.py
cp ./build/_oqspython.so $CP_PATH/_oqspython.so
touch $CP_PATH/__init__.py