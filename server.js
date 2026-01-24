export default {
  fetch(req, env) {
    return Response.json({
      keys: Object.keys(env),
      exists_MYVAR: !!env.MY_VAR,
      val_MYVAR: env.MY_VAR ?? null
    })
  }
}
