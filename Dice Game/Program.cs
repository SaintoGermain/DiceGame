using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SHA3.Net;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace DiceGame{
    public class HMACSHA3_256 : System.Security.Cryptography.HMAC;
    class Program{
        static void Main(string[] args){
                try{
                    // Parse dice configurations from command-line arguments
                    var diceParse = new DiceParse();
                    var diceL = diceParse.Parse(args);
                    var diceL2 = diceParse.Parse(args);

                    // Game initialization
                    var random = new SecureRandomGenerator();
                    var probabilityCalculator = new ProbabilityDiceFaces();
                    var helpTable = new HelpTable(probabilityCalculator, diceL2);
                    var fair = new FairPlay(random);
                    var throws = new Throws();

                    var game = new DiceGame(diceL, diceL2, random, helpTable, fair, throws);
                    game.Start();
            }
            catch (ArgumentException e){
                Console.WriteLine($"Error: {e.Message}");
                Console.WriteLine("Input values example: dotnet run \"2,2,4,4,9,9\" \"6,8,1,1,8,6\" \"7,5,3,7,5,3\"");
            }
        }
    }

    class DiceParse{
        public List<Dice> Parse(string[] args){
            if(args.Length<3){
                throw new ArgumentException("The number of dices must be more than 2");
            }
            var diceL = new List<Dice>();

            foreach (var arg in args){
                var sides = arg.Split(',').Select(int.Parse).ToArray();
                diceL.Add(new Dice(sides));
            }
            return diceL;
        }
    }
    class Dice{
        public int[] Sides{get;}

        public Dice(int[] sides){
            if(sides.Length != 6 || sides.Any(s => s <= 0)){
                throw new ArgumentException("The number of sides is different from 6 or you typed a negative integer");
            }
            Sides = sides;
        }
    }

    class SecureRandomGenerator
    {
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        public int GenerateUniform(int min, int max)
        {
            var range = (long)max - min;
            var bytes = new byte[8];
            long randomValue;

            do
            {
                rng.GetBytes(bytes);
                randomValue = BitConverter.ToInt64(bytes, 0) & long.MaxValue;
            } while (randomValue >= long.MaxValue - (long.MaxValue % range));

            return (int)(min + (randomValue % range));
        }

        public byte[] GenerateKey(int length){

            using (var rng = RandomNumberGenerator.Create()){
                byte[] key = new byte[length];
                rng.GetBytes(key);
                using (var sha3 = Sha3.Sha3256()){
                    return sha3.ComputeHash(key);
                }
            }
        }

        public string CalculateHMAC(byte[] key, string message){
            var hmac = new HMac(new Sha3Digest(256));
            string keyHex = BitConverter.ToString(key).Replace("-", "").ToUpper();

            byte[] keyHexToByte = Encoding.UTF8.GetBytes(keyHex);


            hmac.Init(new KeyParameter(keyHexToByte));
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.BlockUpdate(messageBytes, 0, messageBytes.Length);
            hmac.DoFinal(result, 0);

            return BitConverter.ToString(result).Replace("-", "").ToUpper();

        }

    }


    class FairPlay
    {
        private readonly SecureRandomGenerator random;

        public FairPlay(SecureRandomGenerator random) => this.random = random;

        public int GenerateFairNumber(int range, out byte[] secretKey, out string hmac)
        {
            string numToSt;
            secretKey = random.GenerateKey(32);
            var number = random.GenerateUniform(0, range);
            numToSt = number.ToString();
            hmac = random.CalculateHMAC(secretKey, numToSt);
            return number;
        }

        public int SecGenFairNumber(int range, out byte[] secretKey, out string hmac){
            string numToSt;
            secretKey = random.GenerateKey(32);
            var number = random.GenerateUniform(2, range);
            numToSt = number.ToString();
            hmac = random.CalculateHMAC(secretKey, numToSt);
            return number;
        }
    }

    class ProbabilityDiceFaces{
        public double Probability(Dice diceA, Dice diceB){
            int wins = 0;
            int diceCombinations = diceA.Sides.Length * diceB.Sides.Length;

            foreach (int a in diceA.Sides)
            {
                foreach (int b in diceB.Sides)
                {
                    if (a > b)
                    {
                        wins++;
                    }
                }
            }
            return (double)wins / diceCombinations;
        }   
    }

    class HelpTable{
        private readonly ProbabilityDiceFaces calculator;
        private readonly List<Dice> diceL;

        public HelpTable(ProbabilityDiceFaces calculator, List<Dice> diceL)
        {
            this.calculator = calculator;
            this.diceL = diceL;
        }

        public void Display()
        {
            int cellWidth = 15;
            int totalWidth = cellWidth * (diceL.Count + 2) + (diceL.Count);

            string divider = "+" + new string('-', totalWidth - 2) + "+";

            Console.WriteLine("Probability Table:");
            Console.WriteLine($"|{"User's Dice ↓".PadRight(cellWidth)}| {string.Join(" | ", diceL.Select(d => $"[{string.Join(",", d.Sides)}]".PadRight(cellWidth)))} |");
            Console.WriteLine(divider);

            for (int i = 0; i < diceL.Count; i++)
            {
                Console.Write($"|[{string.Join(",", diceL[i].Sides)}]".PadRight(cellWidth) + " | ");

                for (int j = 0; j < diceL.Count; j++)
                {
                    var probability = i == j ? 0 : calculator.Probability(diceL[i], diceL[j]);
                    Console.Write($"{probability.ToString("F4")}".PadLeft(cellWidth) + " | ");
                }
                Console.WriteLine();
                Console.WriteLine(divider);
            }
        }
    }

    class Throws{
        
    }

    class DiceGame{
        private readonly List<Dice> diceL, diceL2;
        private readonly SecureRandomGenerator random;
        private readonly HelpTable helpTable;
        private readonly FairPlay fair;
        private readonly Throws throws;
        public DiceGame(List<Dice> diceL, List<Dice> diceL2, SecureRandomGenerator random, HelpTable helpTable, FairPlay fair, Throws throws)
        {
            this.diceL = diceL;
            this.random = random;
            this.helpTable = helpTable;
            this.fair = fair;
            this.diceL2 = diceL2;
        }
        public void PlayTurn(FairPlay fair, Dice pcDice, Dice usDice, Random rnd, Action displayHelp)
        {
            Console.WriteLine($"It's time for my throw");
            Console.WriteLine($"I selected a random number in the range 2 to 7");

            int computerNumberMod = fair.SecGenFairNumber(8, out var secretKey2, out var hmac2);
            Console.WriteLine($"Computer's HMAC: {hmac2}");

            int userNumberM = 0;
            while (true)
            {
                Console.WriteLine($"Add your number for modulo 6:");
                for (int i = 2; i < 8; i++)
                {
                    Console.WriteLine($"[{i}]: {i}");
                }
                Console.WriteLine("X - Exit");
                Console.WriteLine("? - Help");

                string userNumberMod = Console.ReadLine();
                if (userNumberMod?.ToUpper() == "X")
                {
                    Console.WriteLine("Thanks for playing!");
                    Environment.Exit(0);
                }

                if (userNumberMod?.ToUpper() == "?")
                {
                    displayHelp();
                    continue;
                }

                if (int.TryParse(userNumberMod, out userNumberM) && userNumberM >= 2 && userNumberM <= 7)
                {
                    break;
                }

                Console.WriteLine("Invalid input. Please try again.");
            }

            Console.WriteLine($"You chose number: {userNumberM}");
            Console.WriteLine($"My number is: {computerNumberMod}");
            Console.WriteLine($"Secret key: {BitConverter.ToString(secretKey2).Replace("-", "").ToUpper()}");


            int mod = (userNumberM + computerNumberMod) % 6;
            Console.WriteLine($"The result is: {userNumberM} + {computerNumberMod} = {mod} (Modulo 6)");

            int pcThrow = pcDice.Sides[rnd.Next(pcDice.Sides.Length)];
            Console.WriteLine($"My throw is: {pcThrow}");

            Console.WriteLine($"It's time for your throw");
            Console.WriteLine($"I selected a random number in the range 2 to 7");

            computerNumberMod = fair.SecGenFairNumber(8, out secretKey2, out hmac2);
            Console.WriteLine($"Computer's HMAC: {hmac2}");

            userNumberM = 0;
            while (true)
            {
                Console.WriteLine($"Add your number for modulo 6:");
                for (int i = 2; i < 8; i++)
                {
                    Console.WriteLine($"[{i}]: {i}");
                }
                Console.WriteLine("X - Exit");
                Console.WriteLine("? - Help");

                string userNumberMod = Console.ReadLine();
                if (userNumberMod?.ToUpper() == "X")
                {
                    Console.WriteLine("Thanks for playing!");
                    Environment.Exit(0);
                }

                if (userNumberMod?.ToUpper() == "?")
                {
                    displayHelp();
                    continue;
                }

                if (int.TryParse(userNumberMod, out userNumberM) && userNumberM >= 2 && userNumberM <= 7)
                {
                    break;
                }

                Console.WriteLine("Invalid input. Please try again.");
            }

            Console.WriteLine($"You chose number: {userNumberM}");
            Console.WriteLine($"My number is: {computerNumberMod}");
            Console.WriteLine($"Secret key: {BitConverter.ToString(secretKey2).Replace("-", "").ToUpper()}");


            mod = (userNumberM + computerNumberMod) % 6;
            Console.WriteLine($"The result is: {userNumberM} + {computerNumberMod} = {mod} (Modulo 6)");

            int usThrow = usDice.Sides[rnd.Next(usDice.Sides.Length)];
            Console.WriteLine($"Your throw is: {usThrow}");

            if (usThrow > pcThrow)
            {
                Console.WriteLine($"You win! ({usThrow} > {pcThrow})");
            }
            else
            {
                Console.WriteLine($"You lose! ({pcThrow} > {usThrow})");
            }
        }


        public void Start(){
            var computerNumber=0;
            var computerNumberMod=0;
            int usThrow,pcThrow;
            Dice pcDice;
            Dice usDice;
            var UsDice=0;
            int userNumber, userDiceIndex, computerDiceIndex, userNumberM, mod;
            Random rnd = new Random();

            Console.WriteLine("Welcome to the Dice Game!");
            Console.WriteLine("I selected a random number between 0 and 2");
            computerNumber = fair.GenerateFairNumber(3, out var secretKey, out var hmac);
            Console.WriteLine($"Computer's HMAC: {hmac}");
            Console.WriteLine("Try to guess my selection");
            while(true){ //Menu           
                Console.WriteLine("Select a number between 0 and 2: ");
                Console.WriteLine("X - Exit");
                Console.WriteLine("? - Help");
                string input = Console.ReadLine();
                if (input?.ToUpper() == "X" || input?.ToUpper() == "x")
                {
                    Console.WriteLine("Thanks for playing!");
                    Environment.Exit(0);
                }

                if (int.TryParse(input, out userNumber) && userNumber >= 0 && userNumber <= 2)
                {
                    break;
                }

                if (input?.ToUpper() == "?")
                {
                    helpTable.Display();
                }
            }
            Console.WriteLine($"My number is: {computerNumber}");
            Console.WriteLine($"Secret key: {BitConverter.ToString(secretKey).Replace("-", "").ToUpper()}");
            if(userNumber==computerNumber){
                Console.WriteLine("You guessed right, you are first to choose!");
                while (true){
                    Console.WriteLine("Choose an option ");
                    for (int i = 0; i < diceL.Count; i++)
                    {
                        Console.WriteLine($"[{i}]: {string.Join(",", diceL[i].Sides)}");
                    }
                    Console.WriteLine("X - Exit");
                    Console.WriteLine("? - Help");

                    string input = Console.ReadLine();

                    if (input?.ToUpper() == "X" || input?.ToUpper() == "x")
                    {
                        Console.WriteLine("Thanks for playing!");
                        Environment.Exit(0);
                    }

                    if (input?.ToUpper() == "?")
                    {
                        helpTable.Display();
                    }

                    if (!int.TryParse(input, out userDiceIndex))
                    {
                        Console.WriteLine("You must type an integer number");
                        continue;
                    }

                    if (userDiceIndex < 0 || userDiceIndex >= diceL.Count)
                    {
                        Console.WriteLine($"The dice {userDiceIndex} doesn't exist in the list");
                        continue;
                    }

                    break;
                }
                usDice = diceL[userDiceIndex];
                diceL.RemoveAt(userDiceIndex);
                Console.WriteLine($"You choose: {userDiceIndex}");
                Console.WriteLine($"Your dice: {string.Join(",", usDice.Sides)}");

                computerDiceIndex = rnd.Next(diceL.Count);
                pcDice = diceL[computerDiceIndex];
                diceL.RemoveAt(computerDiceIndex);
                Console.WriteLine($"I choose the dice: {string.Join(",", pcDice.Sides)}");
                PlayTurn(fair, pcDice, usDice, rnd, helpTable.Display);
            }else{
                computerDiceIndex = rnd.Next(diceL.Count);
                pcDice = diceL[computerDiceIndex];
                diceL.RemoveAt(computerDiceIndex);
                Console.Write("I choose first, ");
                Console.WriteLine($"I choose the dice: {string.Join(",", pcDice.Sides)}");

                Console.WriteLine("Your turn to choose");
                while (true){
                    Console.WriteLine("Choose an option ");
                    for (int i = 0; i < diceL.Count; i++)
                    {
                        Console.WriteLine($"[{i}]: {string.Join(",", diceL[i].Sides)}");
                    }
                    Console.WriteLine("X - Exit");
                    Console.WriteLine("? - Help");
                    
                    string input = Console.ReadLine();

                    if (input?.ToUpper() == "X" || input?.ToUpper() == "x")
                    {
                        Console.WriteLine("Thanks for playing!");
                        Environment.Exit(0);
                    }

                    if (input?.ToUpper() == "?")
                    {
                        helpTable.Display();
                    }

                    if (!int.TryParse(input, out userDiceIndex))
                    {
                        Console.WriteLine("You must type an integer number");
                        continue;
                    }

                    if (userDiceIndex < 0 || userDiceIndex >= diceL.Count)
                    {
                        Console.WriteLine($"The dice {userDiceIndex} doesn't exist in the list");
                        continue;
                    }

                    break;
                }
                usDice = diceL[userDiceIndex];
                diceL.RemoveAt(userDiceIndex);
                Console.WriteLine($"You choose: {userDiceIndex}");
                Console.WriteLine($"Your dice: {string.Join(",", usDice.Sides)}");
                PlayTurn(fair, pcDice, usDice, rnd, helpTable.Display);
            }
        }
    }
}