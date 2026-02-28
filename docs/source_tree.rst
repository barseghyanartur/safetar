Project source-tree
===================

Below is the layout of the project (to 10 levels), followed by
the contents of each key file.

.. code-block:: text
   :caption: Project directory layout

   safetar/
   ├── src
   │   └── safetar
   │       ├── tests
   │       │   ├── __init__.py
   │       │   ├── conftest.py
   │       │   ├── test_guard.py
   │       │   ├── test_integration.py
   │       │   ├── test_sandbox.py
   │       │   └── test_streamer.py
   │       ├── __init__.py
   │       ├── _core.py
   │       ├── _events.py
   │       ├── _exceptions.py
   │       ├── _guard.py
   │       ├── _sandbox.py
   │       ├── _streamer.py
   │       └── py.typed
   ├── .coveralls.yml
   ├── conftest.py
   ├── CONTRIBUTING.rst
   ├── docker-compose.yml
   ├── Dockerfile
   ├── Makefile
   ├── pyproject.toml
   ├── README.rst
   └── tox.ini

.coveralls.yml
--------------

.. literalinclude:: ../.coveralls.yml
   :language: yaml
   :caption: .coveralls.yml

CONTRIBUTING.rst
----------------

.. literalinclude:: ../CONTRIBUTING.rst
   :language: rst
   :caption: CONTRIBUTING.rst

README.rst
----------

.. literalinclude:: ../README.rst
   :language: rst
   :caption: README.rst

conftest.py
-----------

.. literalinclude:: ../conftest.py
   :language: python
   :caption: conftest.py

docker-compose.yml
------------------

.. literalinclude:: ../docker-compose.yml
   :language: yaml
   :caption: docker-compose.yml

pyproject.toml
--------------

.. literalinclude:: ../pyproject.toml
   :language: toml
   :caption: pyproject.toml

src/safetar/__init__.py
-----------------------

.. literalinclude:: ../src/safetar/__init__.py
   :language: python
   :caption: src/safetar/__init__.py

src/safetar/_core.py
--------------------

.. literalinclude:: ../src/safetar/_core.py
   :language: python
   :caption: src/safetar/_core.py

src/safetar/_events.py
----------------------

.. literalinclude:: ../src/safetar/_events.py
   :language: python
   :caption: src/safetar/_events.py

src/safetar/_exceptions.py
--------------------------

.. literalinclude:: ../src/safetar/_exceptions.py
   :language: python
   :caption: src/safetar/_exceptions.py

src/safetar/_guard.py
---------------------

.. literalinclude:: ../src/safetar/_guard.py
   :language: python
   :caption: src/safetar/_guard.py

src/safetar/_sandbox.py
-----------------------

.. literalinclude:: ../src/safetar/_sandbox.py
   :language: python
   :caption: src/safetar/_sandbox.py

src/safetar/_streamer.py
------------------------

.. literalinclude:: ../src/safetar/_streamer.py
   :language: python
   :caption: src/safetar/_streamer.py

src/safetar/tests/__init__.py
-----------------------------

.. literalinclude:: ../src/safetar/tests/__init__.py
   :language: python
   :caption: src/safetar/tests/__init__.py

src/safetar/tests/conftest.py
-----------------------------

.. literalinclude:: ../src/safetar/tests/conftest.py
   :language: python
   :caption: src/safetar/tests/conftest.py

src/safetar/tests/test_guard.py
-------------------------------

.. literalinclude:: ../src/safetar/tests/test_guard.py
   :language: python
   :caption: src/safetar/tests/test_guard.py

src/safetar/tests/test_integration.py
-------------------------------------

.. literalinclude:: ../src/safetar/tests/test_integration.py
   :language: python
   :caption: src/safetar/tests/test_integration.py

src/safetar/tests/test_sandbox.py
---------------------------------

.. literalinclude:: ../src/safetar/tests/test_sandbox.py
   :language: python
   :caption: src/safetar/tests/test_sandbox.py

src/safetar/tests/test_streamer.py
----------------------------------

.. literalinclude:: ../src/safetar/tests/test_streamer.py
   :language: python
   :caption: src/safetar/tests/test_streamer.py
