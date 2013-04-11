-module(sblob).
-export([bitwidth/1, sblob/1]).

bitwidth(N) when is_integer(N),N > 0 -> bitwidth(N div 2, 1).
bitwidth(0, A) -> A;
bitwidth(N, A) -> bitwidth(N div 2, A + 1).

sblob([I|R]) -> sblob(R,element(2,inet_parse:address(I)),0).
sblob([I|R], IP, Mask) -> 
	{OA,OB,OC,OD} = IP,
	{DA,DB,DC,DD} = element(2,inet_parse:address(I)),
	NIP = {OA band DA, OB band DB, OC band DC, OD band DD},
	NMask = binary:decode_unsigned(<<(OA bxor DA), (OB bxor DB), (OC bxor DC), (OD bxor DD)>>,big) bor Mask,
	sblob(R, NIP, NMask);
sblob([], IP, Mask) -> {IP, 32 - bitwidth(Mask)}.
