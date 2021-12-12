### TODOs / FIXMEs

- Do we really need to specify all triggers/actions in the Test constructor already?
  We only need to know the first Trigger. At that point we can generate the test case.

  Given that here, unlike FragAttacks, we don't need to know the IP addresses when
  creating the test cases, we can just generate the full test case on creation?

- Some test cases can be executed against both clients and APs without modifications.
  We can try to explicitly support that.

