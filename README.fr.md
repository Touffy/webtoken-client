# JWT client

Décode et valide des [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT) côté client, en exploitant l'[API Web Crypto](https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface) native pour vérifier les signatures JWS.

webtoken-client fait à peine 5kB minifié et n'a aucune dépendance.

## Pour commencer

```
npm install webtoken-client
```

```javascript
const jwtParser = new JWTParser()
jwtParser.addKey(/* insert your JWK here */)

oAuthLoginAndGetTheTokenSomehow
.then(token => jwtParser.validate(token))
.then(claims => /* là tu te débrouilles ! */)
```

L'objet `claims` promis dans l'example ci-dessus par la méthode `validate` est le contenu décodé du token. La promesse n'est résolue que lorsque JWTParser s'est assuré de la conformité et de la cohérence du token, et en a vérifié la signature. Elle sera rejetée si quelque chose cloche.

## Ça fait quoi ?

JWTParser gère des clés cryptographiques (voir plus bas). La solution la plus sûre est de les coder en dur, ou autrement d'obtenir les clés en local plutôt que via un réseau inconnu. Cela dit, JWTParser est capable d'interpréter les en-têtes du token pour obtenir automatiquement sa clé de vérification si vous le permettez.

L'autre fonction de JWTParser, celle qui vous intéresse en premier lieu, c'est de décoder, valider et vérifier des tokens signés. Certains applications OAuth *peuvent* traiter les JWT comme des chaines opaques côté client. Dans bien d'autres situations, les tokens contiennent des informations utiles, telles que le nom et le courriel d'un utilisateur dans le cas des tokens OpenID.

## Options de gestion de clés

Par défaut, vous devez ajouter toutes les clés de vérification à la main en appelent `addKey()` sur le parseur. Les clés peuvent être passés comme :
* un objet JWK
* une CryptoKey publique (ou symétrique pour HMAC) déjà importée, avec un ID de clé comme second argument

Vous pouvez passer un dictionnaire d'options au constructeur de JWKParser pour activer ces options (désactivées par défaut) :
* *allowInsecure*: accepte les tokens sans signature `(alg=none)`
* *allowTokenKey*: accepte les clés de vérification fournies par le token lui-même (dans l'en-tête `jwk`)
* *trustKeySetOrigins*: une liste blanche sous forme de `RegExp` de tous les [hôtes (domaine:port)](url.spec.whatwg.org/#dom-url-host) d'où des clés peuvent être récupérées lorsque `jku` l'indique ; l'origine complète est implicite puisque HTTPS est le seul protocole autorisé pour ces requêtes.

Par exemple, si vous faites confiance au réseau entre le client et https://jwks.example.org sur n'importe quel port, mais craignez que les tokens eux-mêmes puissent être compromis, vous pourriez spécifier :

```javascript
const parser = new JWKParser({
	trustKeySetOrigins: /^jwks\.example\.org(:\d+)?$/
})
```

Bien sûr, il peut être pratique (**seulement pour tester !**) de relâcher la sécurité au maximum :

```javascript
const parser = new JWKParser({
	allowInsecure: true,
	allowTokenKey: true,
	trustKeySetOrigins: /.*/
})
```

Quoiqu'il en soit, **aucune de ces options ne peut être modifiée après l'intantiation du parseur**.

## Platteformes supportées

*en bref : ça marche sur des navigateurs récents en HTTPS, et en se limitant à des signatures RSA ou HMAC pour le moment.*

webtoken-client dépend de l'API Web Crypto dans les navigateurs récents pour faire son travail bien plus vite, avec bien moins de code, et une meilleure sécurité, que ce qui est possible avec des librairies cryptographiques en JavaScript pur.

Par conséquent, n'essayez pas de le faire tourner dans node.js ou sur Internet Explorer. Par ailleurs, l'API n'étant exposée que sur les pages HTTPS dans certains navigateurs, il faudra peut-être des ajustements pour tester en local.

Évidemment, ça ne marche qu'avec les algorithmes cryptographiques supportés nativement par le navigateur. Actuellement ça veut dire seulement RSASSA-PKCS1-v1_5 et HMAC pour maximiser la compatibilité. Ajoutez ECDSA si vous pouvez attendre Safari 11.

Tant qu'à exiger un navigateur récent, j'ai ciblé ES7 pour la librairie JavaScript transpilée et packagée. Cela exclue quelques versions de navigateurs un peu moins modernes qui supportaient déjà WebCrypto, donc vous devrez recompiler si ces navigaters représentent une base d'utilisateurs importante.

## Licence et crédits

webtoken-client est distribué sous  [licence X11](http://www.gnu.org/licenses/license-list.html#X11License).

Ç'a été développé en partie sur mon temps de travail à la STIME — Les Mousquetaires. D'où cette documentation en français.
