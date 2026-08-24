import { VaultError } from "./errors"

/**
 * Credentials for other services, and how a command is told about them.
 *
 * @remarks
 * A credential is an ordinary vault entry: the token is the sealed value, and
 * everything else about it — which service, which account, when it expires — is
 * metadata, in the clear, because none of it is the secret and all of it is
 * what you want a listing to be able to say.
 */

/** The metadata key naming the service a credential is for. */
export const SERVICE_MARKER = "@vault:service"

/** The metadata key holding the environment variable to set. */
export const ENV_MARKER = "@vault:env"

/** The metadata key holding a credential's extra, non-secret environment. */
export const ENV_EXTRA = "@vault:env-extra"

/**
 * What a credential is, beyond its token.
 *
 * @remarks
 * Everything here is stored in the clear. The token is the only secret, and it
 * is the entry's value.
 */
export type Credential = {
    /** Which service it is for — `npm`, `gitlab`, `github`, or your own name. */
    service: string
    /**
     * The environment variable to put the token in.
     *
     * @remarks
     * Left out, {@link KNOWN_SERVICES} is consulted, and a service not listed
     * there has to say. Guessing a variable name would either do nothing or,
     * worse, put a token somewhere unintended.
     */
    env?: string
    /** The account it belongs to, if that is worth recording. */
    username?: string
    /** Where the service lives, for a self-hosted one. */
    url?: string
    /** What it is allowed to do, as the service words it. */
    scopes?: string[]
    /**
     * More environment to set alongside the token — a registry URL, a host.
     *
     * @remarks
     * Not secret, and not treated as such: it is stored in the clear. Do not
     * put a second token here; give it an entry of its own.
     */
    extra?: Record<string, string>
}

/**
 * The variable each service conventionally reads its token from.
 *
 * @remarks
 * Only services whose convention is unambiguous. Anything not here must say
 * what variable it wants, because a wrong guess puts a live token into an
 * environment that was not asking for it.
 */
export const KNOWN_SERVICES: Record<string, string> = {
    npm: "NPM_TOKEN",
    github: "GITHUB_TOKEN",
    gitlab: "GITLAB_TOKEN",
    cargo: "CARGO_REGISTRY_TOKEN",
    docker: "DOCKER_PASSWORD",
    pypi: "TWINE_PASSWORD",
}

/**
 * Which environment variable a credential's token belongs in.
 *
 * @param credential The credential.
 * @returns The variable name.
 * @throws {@link VaultError} 422 when the service is not one we know a
 *   convention for and the credential did not say.
 */
export function variableFor(credential: Credential): string {
    const named = credential.env ?? KNOWN_SERVICES[credential.service]
    if (!named) {
        throw new VaultError(
            `Nothing here knows which environment variable "${credential.service}" reads its ` +
                `token from. Set "env" on the credential to say.`
        )
    }
    return named
}

/** A credential as it is stored in an entry's metadata. */
export function toMetadata(credential: Credential): Record<string, string> {
    const stored: Record<string, string> = {
        [SERVICE_MARKER]: credential.service,
        [ENV_MARKER]: variableFor(credential),
    }

    if (credential.username) stored.username = credential.username
    if (credential.url) stored.url = credential.url
    if (credential.scopes) stored.scopes = credential.scopes.join(",")
    if (credential.extra) stored[ENV_EXTRA] = JSON.stringify(credential.extra)

    return stored
}

/**
 * A credential back out of an entry's metadata.
 *
 * @param metadata What the entry holds.
 * @returns The credential, without its token — that is the entry's value, and
 *   comes out of `open` like any other secret.
 * @throws {@link VaultError} 422 when the entry is not a credential.
 */
export function fromMetadata(metadata: Record<string, string>): Credential {
    const service = metadata[SERVICE_MARKER]
    if (service === undefined) throw new VaultError("That entry is not a credential.")

    const credential: Credential = { service }
    const env = metadata[ENV_MARKER]
    if (env) credential.env = env
    if (metadata.username) credential.username = metadata.username
    if (metadata.url) credential.url = metadata.url
    if (metadata.scopes) credential.scopes = metadata.scopes.split(",")
    if (metadata[ENV_EXTRA]) {
        credential.extra = JSON.parse(metadata[ENV_EXTRA]) as Record<string, string>
    }

    return credential
}
