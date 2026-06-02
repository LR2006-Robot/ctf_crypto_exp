#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import *
from ortools.sat.python import cp_model
from tqdm import trange

def next_prime(n):
    while True:
        if isPrime(n): return n
        n += 1

class Gao:
    def __init__(self):
        self.conn = remote("node1.anna.nssctf.cn", 27191)
        self.n = None            # 真实的 secret 比特长度 l
        self.m_list = []
        self.u_list = []
        self.first_done = False

    def get_nums(self):
        if not self.first_done:
            # ---------- 第一次请求：探测 l ----------
            self.conn.sendlineafter('[Q]uit\n', 'G')
            s = 2**117
            t = 2**117
            self.conn.sendlineafter('s, t: \n', f'{s},{t}')
            line = self.conn.recvline()
            if b'requirements' in line:
                self.conn.close()
                die("First trial rejected. Try a different bl.")
            n_val = int(line.split(b' = ')[1])

            # 估算并验证 l
            l_guess = n_val.bit_length() // 2
            found_l = None
            for delta in range(-2, 3):
                l_test = l_guess + delta
                r_test = next_prime(s * t ^ 2**l_test)
                if n_val % r_test == 0:
                    found_l = l_test
                    self.r_first = r_test
                    break
            if found_l is None:
                self.conn.close()
                die("Failed to determine l")
            self.n = found_l
            print(f"[+] Real l = {self.n}")

            # 用第一次的数据构造第一组方程
            r = self.r_first
            u = n_val // r
            u1 = sum(map(int, f'{u:b}'))
            u1 -= 1                     # 最高位已知为1
            m = []
            rbits = list(map(int, f'{r:b}'))[1:]   # 去掉最高位
            u1 -= (1 - rbits[0]) + (1 - rbits[-1])  # 首尾已知为1
            for ri in rbits[1:-1]:
                if ri == 0:
                    m.append(1)
                else:
                    m.append(-1)
                    u1 -= 1
            self.m_list.append(m)
            self.u_list.append(u1)
            self.first_done = True
        else:
            # ---------- 后续请求：已知 l ----------
            self.conn.sendlineafter('[Q]uit\n', 'G')
            s = getRandomNBitInteger(self.n // 2 - 1)
            t = getRandomNBitInteger(self.n // 2 - 1)
            r = next_prime(s * t ^ 2**self.n)
            self.conn.sendlineafter('s, t: \n', f'{s},{t}')
            line = self.conn.recvline()
            n_val = int(line.split(b' = ')[1])
            assert n_val % r == 0
            u = n_val // r
            u1 = sum(map(int, f'{u:b}'))
            u1 -= 1
            m = []
            rbits = list(map(int, f'{r:b}'))[1:]
            u1 -= (1 - rbits[0]) + (1 - rbits[-1])
            for ri in rbits[1:-1]:
                if ri == 0:
                    m.append(1)
                else:
                    m.append(-1)
                    u1 -= 1
            self.m_list.append(m)
            self.u_list.append(u1)

    def gao_ortools(self):
        model = cp_model.CpModel()
        my_vars = [model.NewIntVarFromDomain(cp_model.Domain.FromValues([0, 1]), f'x_{i}')
                   for i in range(self.n - 2)]
        for i in trange(self.n // 2):
            model.Add(sum(x * y for x, y in zip(self.m_list[i], my_vars)) == self.u_list[i])
        solver = cp_model.CpSolver()
        status = solver.Solve(model)
        if status == cp_model.OPTIMAL or status == cp_model.FEASIBLE:
            solution = [solver.Value(x) for x in my_vars]
        else:
            raise Exception("No solution found")
        p_bits = [1] + solution + [1]
        self.p = int(''.join(map(str, p_bits)), 2)

    def submit_answer(self):
        self.conn.sendlineafter('[Q]uit\n', 'S')
        self.conn.sendlineafter('secret: \n', str(self.p))
        self.conn.interactive()

    def gao(self):
        print('Building equations...')
        # 先做一次请求，同时获取 l 和第一组方程
        self.get_nums()
        # 总共需要 l//2 组，已经有一组
        required = self.n // 2
        for i in trange(required - 1):
            self.get_nums()
        print('Solving with OR-Tools...')
        self.gao_ortools()
        self.submit_answer()

if __name__ == '__main__':
    g = Gao()
    g.gao()


'''
#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from random import *
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def next_prime(n):
	while True:
		if isPrime(n): return n
		else: n += 1

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::     Welcome to the Nahan Maskara cryptography task!      ::.", border)
	pr(border, ".: Your mission is to find flag by analysing the Nahan Maskara :.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	secret = getPrime(len(flag) << 3)
	l, c, step = secret.bit_length(), 0, secret.bit_length() >> 1
	while True:
		pr(f"{border} Options: \n{border}\t[G]et Nahan value! \n{border}\t[S]end secret! \n{border}\t[Q]uit")
		R, _b = [], False
		ans = sc().decode().strip().lower()
		if ans == 'g':
			pr(border, 'Now please provide two integers s, t: ')
			inp = sc().decode().strip()
			try:
				s, t = [int(_) for _ in inp.split(',')]
				if all(3 * l > 6 * _.bit_length() > 2 * l for _ in (s, t)):
					_b = True
			except:
				die(border, f"The input you provided is not valid!")
			if _b:
				r = next_prime(s * t ^ 2 ** l)
				if r in R:
					die(border, 'You cannot use repeated integers! Bye!!')
				else:
					R.append(r)
				u = list(bin(secret ^ r)[2:])
				shuffle(u)
				pr(border, f'n = {r * int("".join(u), 2)}')
				if c >= step:
					die(border, f'You can get Nahan value at most {step} times! Bye!!')
				c += 1
			else:
				die(border, f"Your input does not meet the requirements!!!")
		elif ans == 's':
			pr(border, "Please send secret: ")
			_secret = sc().decode()
			try:
				_secret = int(_secret)
			except:
				die(border, "The secret is incorrect! Quitting...")
			if _secret == secret:
				die(border, f"Congrats, you got the flag: {flag}")
			else:
				die(border, "The secret is incorrect! Quitting...")
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()
'''