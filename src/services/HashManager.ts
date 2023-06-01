import dotenv from "dotenv"
import bcrypt from "bcryptjs"

dotenv.config()

export class HashManager {

    public hash = async (plainText: string) : Promise<string> => {
        const rounds = Number(process.env.BCRYPT_COST)
        const salt = await bcrypt.genSalt(rounds)
        const hash = await bcrypt.hash(plainText, salt)
        return hash
    }

    public compare = async (
        plainText: string, // input do usuário
        hash: string // senha salva no banco
    ): Promise<boolean> => {
        return bcrypt.compare(plainText, hash)
    }

}