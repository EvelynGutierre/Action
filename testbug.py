import random
import time

def main():
    random.seed(int(time.time()))
    alpha = random.randint(0, 7)
    print("Hello World.")
    beta = 2

    print("Alpha is set to is %s" % alpha)
    print("Kiwi is set to is %s" % beta)

if __name__ == "__main__":
    main()