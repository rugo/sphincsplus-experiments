import sys
from subprocess import check_output, DEVNULL


FILE_FIELDS = [
    "sig_size",
    "sign_n_hashcalls",
    "verif_n_hashcalls",
    "prob_forg",
    "param_h",
    "param_d",
    "param_b",
    "param_k",
    "param_w"
]


TEMPLATE_FILE = "params/params-sphincs-sha2-tests.h.template"
PARAM_FILE = "params/params-sphincs-sha2-tests.h"


def read_file(filename):
    params = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                row = line.strip().split()
                params.append(
                    dict(
                        zip(
                            FILE_FIELDS, [int(float(x)) for x in row]
                        )
                    )
                ) 
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    
    return params


def write_params(params):
    content = open(TEMPLATE_FILE).read()

    for k in params:
        content = content.replace(f"%%{k}%%", str(params[k]))

    open(PARAM_FILE, "w").write(content)


def run_benchmarks():
    check_output("make clean benchmarks", shell=True, stderr=DEVNULL)
    print(
        check_output("test/benchmark").decode()
    )


if __name__ == "__main__":
    # Check if filename is provided as argument
    if len(sys.argv) < 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)
    
    bench = True

    if "--no-bench" in sys.argv:
        bench = False

    filename = sys.argv[1]
    params = read_file(filename)

    for para in params:
        print(50 * "*")
        print(para)
        write_params(para)
        if bench:
            run_benchmarks()
