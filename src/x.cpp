#include <prng/prng.hpp>
#include <aes/aes.hpp>
#include <sha/sha.hpp>
#include <ring/ring.hpp>
#include <QFile>

#define BUFFERSIZE 1024
#define SALTSIZE 1024
#define IVSIZE 16
#define MUTATIONINTERVAL 16
#define AESKEYLENGTH 32
#define RINGKEYLENGTH 32

bool encodeFile(const char* inputFile, const char* key, unsigned int keyLength)
{
	printf("encoding %s", inputFile);
	char salt[SALTSIZE];
	char iv[IVSIZE];
	Prng prng;
	prng.generate(salt, SALTSIZE);
	Sha sha;
	char hashedKey[RINGKEYLENGTH];
	sha.update(key, keyLength);
	sha.getHash(hashedKey);
	Ring ring(hashedKey, RINGKEYLENGTH, salt, SALTSIZE, MUTATIONINTERVAL);
	Aes aes(hashedKey, AESKEYLENGTH, iv, IVSIZE, true);
	char outputFile[strlen(inputFile)+4+1];
	strcpy(outputFile, inputFile);
	strcat(outputFile, ".enc");
	QFile out(outputFile);
	if (out.exists())
	{
		printf("\rfailed to encode %s: outputfile already exists\n", inputFile);
		return false;
	}
	if (!out.open(QIODevice::WriteOnly))
	{
		printf("\r                                                                                                                                \rfailed to encode %s: outputfile not openable\n", inputFile);
		return false;
	}
	if (out.write(salt, SALTSIZE) != SALTSIZE)
	{
		printf("\r                                                                                                                                \rfailed to encode %s: outputfile not writeable\n", inputFile);
		out.close();
		out.remove();
		return false;
	}
	if (out.write(iv, IVSIZE) != IVSIZE)
	{
		printf("\r                                                                                                                                \rfailed to encode %s: outputfile not writeable\n", inputFile);
		out.close();
		out.remove();
		return false;
	}
	QFile in(inputFile);
	if (!in.open(QIODevice::ReadOnly))
	{
		printf("\r                                                                                                                                \rfailed to encode %s: inputfile not openable\n", inputFile);
		out.close();
		out.remove();
		return false;
	}
	unsigned int treated = 0;
	unsigned int toTreat = in.size();
	while (treated < toTreat)
	{
		printf("\r                                                                                                                                \rencoding %s: %.1f %%", inputFile, (float)(treated*100)/toTreat);
		unsigned int bufSize = BUFFERSIZE;
		if (treated+bufSize > toTreat)
		{
			bufSize = toTreat-treated;
		}
		char buf[bufSize];
		if (in.read(buf, bufSize) != bufSize)
		{
			printf("\r                                                                                                                                \rfailed to encode %s: inputfile not readable\n", inputFile);
			in.close();
			out.close();
			out.remove();
			return false;
		}
		sha.update(buf, bufSize);
		ring.encode(buf, bufSize);
		aes.encode(buf, bufSize);
		if (out.write(buf, bufSize) != bufSize)
		{
			printf("\r                                                                                                                                \rfailed to encode %s: outputfile not writeable\n", inputFile);
			in.close();
			out.close();
			out.remove();
			return false;
		}
		treated += bufSize;
	}
	in.close();
	printf("\r                                                                                                                                \rencoding %s: %.1f %%", inputFile, (float)(treated*100)/toTreat);
	char hash[sha.size()];
	sha.getHash(hash);
	if (out.write(hash, sha.size()) != sha.size())
	{
		printf("\r                                                                                                                                \rfailed to encode %s: outputfile not writeable\n", inputFile);
		out.close();
		out.remove();
		return false;
	}
	out.close();
	if (!in.remove())
	{
		return false;
	}
	printf("\r                                                                                                                                \rsucceed encoding %s\n", inputFile);
	return true;
}

bool decodeFile(const char* inputFile, const char* key, unsigned int keyLength)
{
	printf("decoding %s", inputFile);
	QFile in(inputFile);
	if (!in.open(QIODevice::ReadOnly))
	{
		printf("\r                                                                                                                                \rfailed to decode %s: inputfile not openable\n", inputFile);
		return false;
	}
	char salt[SALTSIZE];
	if (in.read(salt, SALTSIZE) != SALTSIZE)
	{
		printf("\r                                                                                                                                \rfailed to decode %s: inputfile not readable\n", inputFile);
		in.close();
		return false;
	}
	char iv[IVSIZE];
	if (in.read(iv, IVSIZE) != IVSIZE)
	{
		printf("\r                                                                                                                                \rfailed to decode %s: inputfile not readable\n", inputFile);
		in.close();
		return false;
	}
	Sha sha;
	char hashedKey[RINGKEYLENGTH];
	sha.update(key, keyLength);
	sha.getHash(hashedKey);

	Ring ring(hashedKey, RINGKEYLENGTH, salt, SALTSIZE, MUTATIONINTERVAL);
	Aes aes(hashedKey, AESKEYLENGTH, iv, IVSIZE, false);
	char outputFile[strlen(inputFile)-4+1];
	strncpy(outputFile, inputFile, strlen(inputFile)-4);
	QFile out(outputFile);
	if (out.exists())
	{
		printf("\nfailed to decode %s: outputfile already exists\n", inputFile);
		in.close();
		return false;
	}
	if (!out.open(QIODevice::WriteOnly))
	{
		printf("\r                                                                                                                                \rfailed to decode %s: outputfile not openable\n", inputFile);
		in.close();
		return false;
	}
	unsigned int toTreat = in.size()-SALTSIZE-IVSIZE-sha.size();
	unsigned int treated = 0;
	while (treated < toTreat)
	{
		printf("\r                                                                                                                                \rdecoding %s: %.1f %%", inputFile, (float)(treated*100)/toTreat);
		unsigned int bufSize = BUFFERSIZE;
		if (treated+bufSize > toTreat)
		{
			bufSize = toTreat-treated;
		}
		char buf[bufSize];
		if (in.read(buf, bufSize) != bufSize)
		{
			printf("\r                                                                                                                                \rfailed to decode %s: inputfile not readable\n", inputFile);
			in.close();
			out.close();
			out.remove();
			return false;
		}
		aes.decode(buf, bufSize);
		ring.decode(buf, bufSize);
		sha.update(buf, bufSize);
		if (out.write(buf, bufSize) != bufSize)
		{
			printf("\r                                                                                                                                \rfailed to decode %s: outputfile not writeable\n", inputFile);
			in.close();
			out.close();
			out.remove();
			return false;
		}
		treated += bufSize;
	}
	out.close();
	printf("\r                                                                                                                                \rdecoding %s: %.1f %%", inputFile, (float)(treated*100)/toTreat);
	char hash[sha.size()];
	if (in.read(hash, sha.size()) != sha.size())
	{
		printf("\r                                                                                                                                \rfailed to decode %s: inputfile not readable\n", inputFile);
		in.close();
		out.remove();
		return false;
	}
	in.close();
	if (!sha.matches(hash))
	{
		printf("\r                                                                                                                                \rfailed to decode %s: inputfile modified\n", inputFile);
		out.remove();
		return false;
	}
	if (!in.remove())
	{
		return false;
	}
	printf("\r                                                                                                                                \rsucceed decoding %s\n", inputFile);
	return true;
}

int main(int argc, char* argv[])
{
	bool inputFileParam = false;
	bool keyParam = false;
	bool encodeParam = false;
	bool decodeParam = false;
	bool unknownParam = false;
	char inputFile[1024];
	char key[1024];
	for (int i=1; i<argc; i++)
	{
		if (strcmp(argv[i], "-i") == 0)
		{
			i++;
			if (i<argc)
			{
				strcpy(inputFile, argv[i]);
				inputFileParam = true;
				continue;
			}
		}
		if (strcmp(argv[i], "-k") == 0)
		{
			i++;
			if (i<argc)
			{
				strcpy(key, argv[i]);
				keyParam = true;
				continue;
			}
		}
		if (strcmp(argv[i], "-d") == 0)
		{
			decodeParam = true;
			continue;
		}
		if (strcmp(argv[i], "-e") == 0)
		{
			encodeParam = true;
			continue;
		}
		unknownParam = true;
	}
	if (!encodeParam && !decodeParam)
	{
		encodeParam = true;
	}
	if (!inputFileParam || !keyParam || (encodeParam && decodeParam) || unknownParam)
	{
		printf("%s -i <inputfile> -k <key> [-e|-d]\n", argv[0]);
		return -1;
	}
	bool ret;
	if (encodeParam)
	{
		ret = encodeFile(inputFile, key, strlen(key));
	}
	else
	{
		ret = decodeFile(inputFile, key, strlen(key));
	}
	if (ret)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
