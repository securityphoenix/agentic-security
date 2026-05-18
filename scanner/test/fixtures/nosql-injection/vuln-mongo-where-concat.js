async function search(req, res) {
  const filter = req.query.filter || '';
  const items = await db.collection('items').find({
    $where: 'this.name == "' + filter + '"',  // Vuln: $where string concat.
  }).toArray();
  res.json(items);
}
module.exports = search;
